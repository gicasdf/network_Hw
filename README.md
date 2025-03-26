# network_Hw

mkdir networksecurity_hw1             //폴더 생성
touch sniff_http_hw.c myheader_hw.h   //파일 생성
gedit myheader_hw.h                   //코드 작성
gedit sniff_http_hw.c
gcc -o sniff_http sniff_http_hw.c -lpcap
//-o sniff_http → 실행 파일 이름을 sniff_http로 설정
//-lpcap → PCAP 라이브러리를 사용하기 때문에 추가하여 컴파일

//생성된 파일 실행
sudo ./sniff_http

//다른 cmd 열어서 트래픽 발생시키기
curl http://example.com
