import java.security.MessageDigest
import javax.crypto.spec.SecretKeySpec


fun getMethod(): Int {  // 원하는 암호화 방식을 입력받는 함수
    println()
    while(true) {
        println("원하는 암호화 방식을 선택하세요. (번호입력)")
        println("1. 대칭 암호화")
        println("2. 비대칭 암호화")
        println("3. 해시 함수")
        println("4. 프로그램 종료")
        print("> ")

        val method: Int = readln().toInt()

        if (method in 1..4) {
            return method
        }
        else {
            println("잘못된 입력입니다.")
        }
    }
}


fun getMsg(): String {  // 메시지를 입력받는 함수
    println("메시지를 입력하세요")
    print("> ")

    return readln()
}


fun getMode(): String { // 모드를 입력받는 함수
    while(true) {
        println()
        println("암호화는 E, 복호화는 D를 입력하세요")
        print("> ")
        val mode: String = readln()

        if (mode == "E" || mode == "D") {
            return mode
        }
        else {
            println("잘못된 입력입니다.")
        }
    }
}


fun generateAESKeyFromPassword(password: String): SecretKeySpec {   // 입력받은 패스워드로 암호화 키를 만드는 함수
    val sha256 = MessageDigest.getInstance("SHA-256")
    val hash = sha256.digest(password.toByteArray(Charsets.UTF_8))
    return SecretKeySpec(hash.sliceArray(0 until 16), "AES")
}


fun aes(aes: AES, msg: String, mode: String) {    // AES 암호화 함수
    var operationMode: Int = -1

    while(true) {
        println()
        println("작동 모드를 선택하세요.")
        println("1. ECB 모드")
        println("2. CBC 모드")
        println("3. CFB 모드")
        print("> ")

        operationMode = readln().toInt()

        if (operationMode in 1..3) {
            break
        }
        else {
            println("잘못된 입력입니다.")
        }
    }

    println()
    println("키를 입력하세요")
    print("> ")
    val input: String = readln()
    val key: SecretKeySpec = generateAESKeyFromPassword(input)


    when (mode) {
        "E" -> {    // 암호화 모드
            when (operationMode) {
                1 -> {   // 1번이면 ECB 모드로 암호화
                    val cipherText: String = aes.encryptECB(msg, key)
                    println("암호문: $cipherText")
                }
                2 -> {   // 2번이면 CBC 모드로 암호화
                    val cipherText: String = aes.encryptCBC(msg, key)
                    println("암호문: $cipherText")
                }
                3 -> {   // 3번이면 CFB 모드로 암호화
                    val cipherText: String = aes.encryptCFB(msg, key)
                    println("암호문: $cipherText")
                }
            }
        }
        "D" -> {    // 복호화 모드
            when (operationMode) {
                1 -> {   // 1번이면 ECB 모드로 복호화
                    val plainText: String = aes.decryptECB(msg, key)
                    println("평문: $plainText")
                }
                2 -> {   // 2번이면 CBC 모드로 복호화
                    val plainText: String = aes.decryptCBC(msg, key)
                    println("평문: $plainText")
                }
                3 -> {   // 3번이면 CFB 모드로 복호화
                    val plainText: String = aes.decryptCFB(msg, key)
                    println("평문: $plainText")
                }
            }
        }
        else -> {   // mode 값이 'E' 또는 'D'가 아니면 오류 발생
            println("aes() function error!")
        }
    }
}


fun rsa(rsa: RSA, msg: String, mode: String) { // RSA 암호화 함수
    when (mode) {
        "E" -> {
            val cipherText: String = rsa.encrypt(msg)
            println("암호문: $cipherText")
        }
        "D" -> {
            val plainText: String = rsa.decrypt(msg)
            println("평문: $plainText")
        }
        else -> {
            println("rsa() function error!")
        }
    }
}


fun sha(sha: SHA, msg: String) { // SHA 암호화 함수
    val hash = sha.sha512(msg)
    println("해시 값: $hash")
}


fun clearConsole() {
    Thread.sleep(1000)
    print("\u001b[H\u001b[2J")
    System.out.flush()
}


fun main() {
    // AES 암호화 객체 생성
    val aes = AES()

    // RSA 암호화 객체 생성
    val rsa = RSA()

    // SHA 암호화 객체 생성
    val sha = SHA()

    while(true) {
        when (getMethod()) {
            1 -> {  // 1번 이면 AES 암호화 실행
                println("\n---------------------------------------------------------- AES 암호화 ----------------------------------------------------------")
                val msg: String = getMsg()
                val mode: String = getMode()
                aes(aes, msg, mode)
            }
            2 -> {   // 2번이면 RSA 암호화 실행
                println("\n---------------------------------------------------------- RSA 암호화 ----------------------------------------------------------")
                val msg: String = getMsg()
                val mode: String = getMode()
                rsa(rsa, msg, mode)
            }
            3 -> {  // 3번이면 SHA 암호화 실행
                println("\n---------------------------------------------------------- SHA 암호화 ----------------------------------------------------------")
                val msg: String = getMsg()
                sha(sha, msg)
            }       // 4번이면 프로그램 종료
            4 -> return
        }

        clearConsole()
    }
}