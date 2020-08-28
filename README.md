# ecdsa

간단한 ECDSA 전자서명 및 검증 루틴, Mbedtls 라이브러리를 사용 했습니다. 
인증서는 두개의 SubCA와 Leaf로 구성되어 있고요, make 하면 컴파일 됩니다. (그전에 mbedtls library 설치 해줘야 하고요. ubuntu에서 실행했습니다.)

Simiple ECDSA signature creation and validate example
You can parse the certificate and extract the public key from it and convert to ECDSA context. 

To run this code, you first should install MBEDTLS Library and run make (Ubuntu Environment)
