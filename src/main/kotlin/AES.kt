import java.security.SecureRandom
import java.util.*
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec


class AES {
    companion object {
        private var iv: ByteArray = ByteArray(16)
        private lateinit var ivSpec: IvParameterSpec
    }

    init {
        val random = SecureRandom()
        random.nextBytes(iv)    // iv 생성

        ivSpec= IvParameterSpec(iv)    // 초기화 백터 생성
    }

    public fun encryptECB(plainText: String, key: SecretKey): String {
        var cipherText: String = ""

        try {
            // AES 암호화 객체 생성
            val cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING")

            // 암호화 모드로 설정
            cipher.init(Cipher.ENCRYPT_MODE, key)

            // 암호화
            val encrypted: ByteArray = cipher.doFinal(plainText.toByteArray(Charsets.UTF_8))

            // 암호화된 바이트 배열을 Base64로 인코딩
            cipherText = Base64.getEncoder().encodeToString(encrypted)
        } catch (e: Exception) {
            println("Exception: ${e.message}")
        }

        return cipherText
    }


    public fun decryptECB(cipherText: String, key: SecretKey): String {
        var plainText: String = ""

        try {
            // AES 암호화 객체 생성
            val cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING")

            // 복호화 모드로 설정
            cipher.init(Cipher.DECRYPT_MODE, key)

            // 암호문 Base64로 디코딩
            val decodeBytes: ByteArray = Base64.getDecoder().decode(cipherText)

            // 복호화
            val encrypted: ByteArray = cipher.doFinal(decodeBytes)

            // 복호화된 바이트 배열을 문자열로 변환
            plainText = String(encrypted)
        } catch (e: Exception) {
            println("Exception: ${e.message}")
        }

        return plainText
    }


    public fun encryptCBC(plainText: String, key: SecretKey): String {
        var cipherText: String = ""

        try {
            // AES 암호화 객체 생성
            val cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING")

            // 암호화 모드로 설정
            cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec)

            // 암호화
            val encrypted: ByteArray = cipher.doFinal(plainText.toByteArray(Charsets.UTF_8))

            // 암호화된 바이트 배열 Base64로 인코딩
            cipherText = Base64.getEncoder().encodeToString(encrypted)

        } catch (e: Exception) {
            println("Exception: ${e.message}")
        }

        return cipherText
    }


    public fun decryptCBC(cipherText: String, key: SecretKey): String {
        var plainText: String = ""

        try {
            // AES 암호화 객체 생성
            val cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING")

            // 복호화 모드로 설정
            cipher.init(Cipher.DECRYPT_MODE, key, ivSpec)

            // 암호문 Base64로 디코딩
            val decodeBytes: ByteArray = Base64.getDecoder().decode(cipherText)

            // 복호화
            val decrypted: ByteArray = cipher.doFinal(decodeBytes)

            // 복호화된 바이트 배열을 문자열로 변환
            plainText = String(decrypted)
        } catch (e: Exception) {
            println("Exception: ${e.message}")
        }

        return plainText
    }


    public fun encryptCFB(plainText: String, key: SecretKey): String {
        var cipherText: String = ""

        try {
            // AES 암호화 객체 생성
            val cipher = Cipher.getInstance("AES/CFB/PKCS5Padding")

            // 암호화 모드로 설정
            cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec)

            // 암호화
            val encrypted = cipher.doFinal(plainText.toByteArray(Charsets.UTF_8))

            // 암호화된 바이트 배열 Base64로 인코딩
            cipherText = Base64.getEncoder().encodeToString(encrypted)
        } catch (e: Exception) {
            println("Exception: ${e.message}")
        }

        return cipherText
    }

    public fun decryptCFB(cipherText: String, key: SecretKey): String {
        var plainText: String = ""

        try {
            // AES 암호화 객체 생성
            val cipher = Cipher.getInstance("AES/CFB/PKCS5Padding")

            // 복호화 모드로 설정
            cipher.init(Cipher.DECRYPT_MODE, key, ivSpec)

            // 암호문 Base64로 디코딩
            val decodeBytes: ByteArray = Base64.getDecoder().decode(cipherText)

            // 복호화
            val decrypted = cipher.doFinal(decodeBytes)

            // 복호화된 바이트 배열을 문자열로 변환
            plainText = String(decrypted)
        } catch (e: Exception) {
            println("Exception: ${e.message}")
        }

        return plainText
    }
}