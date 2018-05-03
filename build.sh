gcc -g -O0 src/key.c main.c src/signature.c src/context.c src/multisig.c -L/usr/local/lib -lcrypto

mkdir -p build
gcc -g -c -o build/key.o src/key.c
gcc -g -c -o build/signature.o src/signature.c
gcc -g -c -o build/context.o src/context.c
gcc -g -c -o build/multisig.o src/multisig.c
ar rcs libcschnorr.a build/*.o
