const { DynamoDBClient } = require("@aws-sdk/client-dynamodb");
const { RekognitionClient, DetectFacesCommand } = require("@aws-sdk/client-rekognition");
const { DynamoDBDocumentClient } = require("@aws-sdk/lib-dynamodb");
const { logBusiness } = require("../utils/logger");

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
    async verifyFaceData(){}
    async registerWebAuthnCredential(){}
    async verifyWebAuthnCredential(){}
    async storeBiometricData(){}
    async getBiometricData(){}
    async deleteBiometricData(){}
    async calculateSimilarity(){}
    async verifyWebAuthnAssertion(){}
    async getUserBiometrics(){}
}