class BiometricUtils {
    static validateImageData(base64Image) {
        const base64Regex = /^[A-Za-z0-9+/]*={0,2}$/
        if(!base64Image.test(base64Image)){
            throw new Error('Invalid base64 image format')
        }
        //
        const sizeInBytes = (base64Image.length * (3/4)) - (base64Image.endsWith('==') ? 2 : base64Image.endsWith('=') ? 1 : 0)
        if(sizeInBytes > 5*1024*1024){
            throw new Error("Image to large")
        }
        return true;
    }

    static generateBiometricId(){
        return crypto.randomBytes(32).toString('hex');
    }

    static hashBiometricData(data) {
        return crypto.createHash('sha256').update(JSON.stringify(data)).digest('hex');
    }
}

module.exports = BiometricUtils