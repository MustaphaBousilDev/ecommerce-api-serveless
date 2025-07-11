const { DynamoDBClient, QueryCommand } = require("@aws-sdk/client-dynamodb");
const { RekognitionClient, DetectFacesCommand, Attribute } = require("@aws-sdk/client-rekognition");
const { DynamoDBDocumentClient, GetCommand, PutCommand, DeleteCommand } = require("@aws-sdk/lib-dynamodb");
const { logBusiness, logError } = require("../utils/logger");

class BiometricService {
    constructor(){
        this.rekognitionClient = new RekognitionClient({
            region: process.env.AWS_REGION_NAME
        })
        this.dynamoClient = DynamoDBDocumentClient.from(new DynamoDBClient({
            region: process.env.AWS_REGION_NAME
        }))
        this.biometricTable = process.env.BIOMETRIC_TABLE || 'biometric-data';
    }

    async registerFaceData(email, imageBase64, requestId){
        try {
            logBusiness('face_registration_attempt', null, requestId, {
                email: email.replace(/(.{2})(.*)(@.*)/, '$1***$3')
            })
            const imageBuffer = Buffer.from(imageBase64, 'base64')
            if(imageBuffer.length > 5*1024*1024){
                throw new Error('Image to large (max 5MB)')
            }
            const detectParams = {
                Image: { Bytes: imageBuffer },
                Attributes: ['ALL']
            }
            const detectCommand = new DetectFacesCommand(detectParams)
            const detectResult = await this.rekognitionClient.send(detectCommand)
            if(detectResult.FaceDetails.length === 0){
                throw new Error('No face detected in image')
            }
            if (detectResult.FaceDetails.length > 1) {
                throw new Error('Multiple faces detected - please use image with single face');
            }
            const faceDetail = detectResult.FaceDetails[0];
            if (faceDetail.Confidence < 85) {
                throw new Error(`Face detection confidence too low: ${faceDetail.Confidence}%`);
            }
            const pose = faceDetail.Pose;
            if (Math.abs(pose.Yaw) > 30 || Math.abs(pose.Pitch) > 20 || Math.abs(pose.Roll) > 30) {
                throw new Error('Face positioning not optimal - please look straight at camera');
            }
            const faceHash = crypto.createHash('sha256').update(imageBase64).digest('hex');
                
            const biometricData = {
                userId: email,
                biometricType: 'face',
                faceEncoding: faceHash, // Store hash, not raw image
                confidence: faceDetail.Confidence,
                boundingBox: faceDetail.BoundingBox,
                landmarks: faceDetail.Landmarks,
                pose: faceDetail.Pose,
                quality: faceDetail.Quality,
                createdAt: new Date().toISOString(),
                updatedAt: new Date().toISOString(),
                deviceInfo: {
                    ip: null, // Will be set by controller
                    userAgent: null
                }
            };
            await this.storeBiometricData(email, 'face', biometricData);
            logBusiness('face_registration_success', null, requestId, { 
                email: email.replace(/(.{2})(.*)(@.*)/, '$1***$3'),
                confidence: faceDetail.Confidence
            });
            return {
                success: true,
                confidence: faceDetail.Confidence,
                message: 'Face registered successfully',
                qualityScore: faceDetail.Quality
            };
        } catch(error) {
            logError(error, requestId, null, { 
                operation: 'face_registration',
                email: email.replace(/(.{2})(.*)(@.*)/, '$1***$3')
            });
            throw error;
        }
    }
    async verifyFaceData(email, imageBase64, requestId){
        try {
          logBusiness('facfe_verification_attempt', null, requestId, {
            email: email.replace(/(.{2})(.*)(@.*)/, '$1***$3')
          })
          const storedData = await this.getBiometricData(email, 'face')
          if(!storedData){
            throw new Error('No Face data registered for this user')
          }
          const imageBuffer = Buffer.from(imageBase64, 'base64')
          const detectParams = {
            Image: { Bytes: imageBuffer}, 
            Attribute: ['DEFAULT']
          }
          const detectCommand = new DetectFacesCommand(detectParams)
          const detectResult = await this.rekognitionClient.send(detectCommand)
          if (detectResult.FaceDetails.length === 0) {
                logSecurity('face_verification_no_face', null, requestId, { 
                    email: email.replace(/(.{2})(.*)(@.*)/, '$1***$3') 
                });
                return { verified: false, confidence: 0, reason: 'No face detected' };
          }
          const currentFaceHash = crypto.createHash('sha256').update(imageBase64).digest('hex');
          const similarity = this.calculateSimilarity(storedData.faceEncoding, currentFaceHash);
          const verified = similarity >= 85;
          if (verified) {
                logBusiness('face_verification_success', null, requestId, { 
                    email: email.replace(/(.{2})(.*)(@.*)/, '$1***$3'),
                    confidence: similarity
                });
            } else {
                logSecurity('face_verification_failed', null, requestId, { 
                    email: email.replace(/(.{2})(.*)(@.*)/, '$1***$3'),
                    confidence: similarity,
                    threshold: 85
                });
          }
          return  {
            verified,
            confidence: similarity,
            threshold: 85,
            reason: verified ? 'Face verified Succesfully': 'Face verification failed'
          }

        } catch(error) {
            logError(error, requestId, null, { 
                operation: 'face_verification',
                email: email.replace(/(.{2})(.*)(@.*)/, '$1***$3')
            });
            throw error;
        }
    }
    async registerWebAuthnCredential(email, credentialData, requestId){
        try {
            logBusiness('webauthn_registration_attempt', null, requestId, {
                email: email.replace(/(.{2})(.*)(@.*)/, '$1***$3')
            })
            if(!credentialData || !credentialData.rawId, !credentialData.response){
                throw new Error('Invalid credential data')
            }
            const biometricData = {
                userId: email, 
                biometricType: 'webauthn',
                credentialId: credentialData.id, 
                credentialRawId: credentialData.rawId,
                publicKey: credentialData.response.attestationObject, 
                clientDataJSON: credentialData.response.clientDataJSON, 
                createdAt: new Date().toISOString(),
                updatedAt: new Date().toISOString()
            }
            await this.storeBiometricData(email, 'webauthn', biometricData)
            logBusiness('webauthn_registration_success', null, requestId, {
                email: email.replace(/(.{2})(.*)(@.*)/, '$1***$3'),
                credentialId: credentialData.id
            })
            return {
                success: true, 
                credentialId: credentialData.id, 
                message: 'WebAuthn credential registered successfully'
            }

        } catch(error) {
            logError(error, requestId, null, {
                operation: 'webauthn_registration', 
                email: email.replace(/(.{2})(.*)(@.*)/, '$1***$3')
            })
            throw error;
        }
    }
    verifyWebAuthnAssertion(storedData, assertionData) {
        // Simplified WebAuthn verification
        // In production, use proper WebAuthn verification libraries
        return storedData.credentialId === assertionData.id;
    }
    async storeBiometricData(userId, biometricType, data){
        const params = {
            TableName: this.biometricTable,
            Item: {
                userId,
                biometricType,
                ...data
            }
        };

        const command = new PutCommand(params);
        return await this.dynamoClient.send(command);
    }
    async getBiometricData(userId, biometricType){
        const params = {
            TableName: this.biometricTable,
            Key: {
                userId,
                biometricType
            }
        };

        const command = new GetCommand(params);
        const result = await this.dynamoClient.send(command);
        return result.Item;
    }
    async deleteBiometricData(userId, biometricType) {
        const params = {
            TableName: this.biometricTable,
            Key: {
                userId,
                biometricType
            }
        };

        const command = new DeleteCommand(params);
        return await this.dynamoClient.send(command);
    }
    async calculateSimilarity(hash1, hash2){
        if (hash1 === hash2) return 100;
        
        // Basic hamming distance for demonstration
        let matches = 0;
        const minLength = Math.min(hash1.length, hash2.length);
        
        for (let i = 0; i < minLength; i++) {
            if (hash1[i] === hash2[i]) matches++;
        }
        
        return Math.round((matches / minLength) * 100);
    }
    async verifyWebAuthnAssertion(storedData, assertionData){
        return storedData.credentialId === assertionData.id;
    }
    async getUserBiometrics(userId){
        const params = {
            TableName: this.biometricTable,
            KeyConditionExpression: 'userId = :userId',
            ExpressionAttributeValues: {
                ':userId': userId
            }
        };

        const command = new QueryCommand(params);
        const result = await this.dynamoClient.send(command);
        return result.Items || [];
    }
    async verifyWebAuthnCredential(email, assertionData, requestId) {
        try {
            logBusiness('webauthn_verification_attempt', null, requestId, { 
                email: email.replace(/(.{2})(.*)(@.*)/, '$1***$3') 
            });

            // 1. Get stored credential
            const storedData = await this.getBiometricData(email, 'webauthn');
            if (!storedData) {
                throw new Error('No WebAuthn credential registered for this user');
            }

            // 2. Verify assertion (simplified - in production use proper WebAuthn verification)
            const verified = this.verifyWebAuthnAssertion(storedData, assertionData);

            if (verified) {
                logBusiness('webauthn_verification_success', null, requestId, { 
                    email: email.replace(/(.{2})(.*)(@.*)/, '$1***$3'),
                    credentialId: assertionData.id
                });
            } else {
                logSecurity('webauthn_verification_failed', null, requestId, { 
                    email: email.replace(/(.{2})(.*)(@.*)/, '$1***$3'),
                    credentialId: assertionData.id
                });
            }

            return {
                verified,
                credentialId: assertionData.id,
                reason: verified ? 'WebAuthn verification successful' : 'WebAuthn verification failed'
            };

        } catch (error) {
            logError(error, requestId, null, { 
                operation: 'webauthn_verification',
                email: email.replace(/(.{2})(.*)(@.*)/, '$1***$3')
            });
            throw error;
        }
    }
}

module.exports = new BiometricService();