#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <gmp.h> 
#include "rsa.h"
#include "prf.h"
/* NOTE: a random composite surviving 10 Miller-Rabin tests is extremely
 * unlikely.  See Pomerance et al.:
 * http://www.amps.org/mcom/1993-61-203/S0025-5718-1993-1189518-9/
 * */
#define ISPRIME(x) mpz_probab_prime_p(x,10)
#define NEWZ(x) mpz_t x; mpz_init(x)
#define BYTES2Z(x,buf,len) mpz_import(x,len,-1,1,0,0,buf)
#define Z2BYTES(buf,len,x) mpz_export(buf,&len,-1,1,0,0,x)

/* utility function for read/write mpz_t with streams: */
int zToFile(FILE* f, mpz_t x)
{
	size_t i,len = mpz_size(x)*sizeof(mp_limb_t);
	unsigned char* buf = malloc(len);
	/* force little endian-ness: */
	for (i = 0; i < 8; i++) {
		unsigned char b = (len >> 8*i) % 256;
		fwrite(&b,1,1,f);
	}
	Z2BYTES(buf,len,x);
	fwrite(buf,1,len,f);
	/* kill copy in buffer, in case this was sensitive: */
	memset(buf,0,len);
	free(buf);
	return 0;
}
int zFromFile(FILE* f, mpz_t x)
{
	size_t i,len=0;
	/* force little endian-ness: */
	for (i = 0; i < 8; i++) {
		unsigned char b;
		/* XXX error check this; return meaningful value. */
		fread(&b,1,1,f);
		len += (b << 8*i);
	}
	unsigned char* buf = malloc(len);
	fread(buf,1,len,f);
	BYTES2Z(x,buf,len);
	/* kill copy in buffer, in case this was sensitive: */
	memset(buf,0,len);
	free(buf);
	return 0;
}

int rsa_keyGen(size_t keyBits, RSA_KEY* K)
{
	rsa_initKey(K);
	/* TODO: write this.  Use the prf to get random byte strings of
	 * the right length, and then test for primality (see the ISPRIME
	 * macro above).  Once you've found the primes, set up the other
	 * pieces of the key ({en,de}crypting exponents, and n=pq). */

//~~~~~~~~~~~~~~~~~~~~~~~~Initializing arrays~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~//
	unsigned char* p; // define space for prime p
	unsigned char* q; // define space for prime q
	p = malloc(keyBits/8); //memory allocation
	q = malloc(keyBits/8); //memory allocation
	randBytes(p,keyBits/8);// generate random bytes
	randBytes(q,keyBits/8);// generate random bytes
//~~~~~~~~~~~~~~~~~~~~~~~~Finding the first prime~~~~~~~~~~~~~~~~~~~~~~~~~~~//
	NEWZ(P);// define gmp variable
	BYTES2Z(P,p,keyBits/8); //asigned the randombyte to interger into P
    	NEWZ(nextP); 
    	mpz_nextprime(nextP,P);  //finding a prime for nextP
	if(ISPRIME(nextP)==1)   //makes sure it is prime
	{
		mpz_set(K->p,nextP);    //sets P into the initKey
	}
	else printf("P IS NOT PRIME");
//~~~~~~~~~~~~~~~~~~~~~~~~Finding the second prime~~~~~~~~~~~~~~~~~~~~~~~~~//
	NEWZ(Q);
	BYTES2Z(Q,q,keyBits/8); //asigned the randombyte to interger into Q
	NEWZ(nextQ);
	mpz_nextprime(nextQ,Q);  //finding a prime for nextQ
	if(ISPRIME(nextQ)==1)   //make sure it is prime
	{
		mpz_set(K->q,nextQ);     //sets Q into the initKey
	}
	else printf("Q IS NOT PRIME");
//~~~~~~~~~~~~~~~~~~~~~~~~Computing N~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~//
	NEWZ(N);
	mpz_mul(N,K->p,K->q);          //computes N.
	mpz_set(K->n,N);         //sets N to the initKey
//~~~~~~~~~~~~~~~~~~~~~~~~Computing phi~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~//	
	NEWZ(phi); NEWZ(p1); NEWZ(q1); //creating variables for phi 
	mpz_sub_ui(p1,K->p,1);   //getting P-1
	mpz_sub_ui(q1,K->q,1);   //getting Q-1
	mpz_mul(phi,p1,q1);      
//~~~~~~~~~~~~~~~~~~~~~~~~Computing E~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~//	
	NEWZ(temp);
	// Test - What if we have key size = keyBits/8?
	unsigned char* buffer = malloc(keyBits/8); //create memory

	do{
		randBytes(buffer,keyBits/8); // create randomBytes
		BYTES2Z(K->e,buffer, keyBits/8); // convert and put into e
		mpz_gcd(temp,K->e,phi); //compute gcd(e,phi)
	  }	 
	while(mpz_cmp_ui(temp,1)); // check that the gcd(e,phi) = 1, yes = 0



//~~~~~~~~~~~~~~~~~~~~~~~Computind D~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~//	
	NEWZ(t); //temporary asignment 
	mpz_invert(t,K->e,phi);
	mpz_set(K->d,t);
//~~~~~~~~~~~~~~~~~~~~~~~Clearing memory~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~//
	mpz_clear(P);
	mpz_clear(nextP);
	mpz_clear(Q);
	mpz_clear(nextQ);
	mpz_clear(N);
	mpz_clear(phi);
	mpz_clear(temp);
	mpz_clear(p1);
	mpz_clear(q1);
	mpz_clear(t);
	return 0;
}

size_t rsa_encrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len,
		RSA_KEY* K)
{
	/* TODO: write this.  Use BYTES2Z to get integers, and then
	 * Z2BYTES to write the output buffer. */
	NEWZ(mg);
	NEWZ(ct);

	BYTES2Z(mg,inBuf,len);     
	mpz_powm(ct,mg,K->e,K->n); // ct = message^e mod n
	Z2BYTES(outBuf,len,ct);    

	mpz_clear(mg); mpz_clear(ct);

	return len; /* TODO: return should be # bytes written */
}
size_t rsa_decrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len,
		RSA_KEY* K)
{
	/* TODO: write this.  See remarks above. */
	NEWZ(ct);
	NEWZ(pt);
		
	BYTES2Z(ct,inBuf,len);
	mpz_powm(pt,ct,K->d,K->n); // mg = c^d mod n
	Z2BYTES(outBuf,len,pt);	

	mpz_clear(ct); mpz_clear(pt); 

	return len;
}

size_t rsa_numBytesN(RSA_KEY* K)
{
	return mpz_size(K->n) * sizeof(mp_limb_t);
}

int rsa_initKey(RSA_KEY* K)
{
	mpz_init(K->d); mpz_set_ui(K->d,0);
	mpz_init(K->e); mpz_set_ui(K->e,0);
	mpz_init(K->p); mpz_set_ui(K->p,0);
	mpz_init(K->q); mpz_set_ui(K->q,0);
	mpz_init(K->n); mpz_set_ui(K->n,0);
	return 0;
}

int rsa_writePublic(FILE* f, RSA_KEY* K)
{
	/* only write n,e */
	zToFile(f,K->n);
	zToFile(f,K->e);
	return 0;
}
int rsa_writePrivate(FILE* f, RSA_KEY* K)
{
	zToFile(f,K->n);
	zToFile(f,K->e);
	zToFile(f,K->p);
	zToFile(f,K->q);
	zToFile(f,K->d);
	return 0;
}
int rsa_readPublic(FILE* f, RSA_KEY* K)
{
	rsa_initKey(K); /* will set all unused members to 0 */
	zFromFile(f,K->n);
	zFromFile(f,K->e);
	return 0;
}
int rsa_readPrivate(FILE* f, RSA_KEY* K)
{
	rsa_initKey(K);
	zFromFile(f,K->n);
	zFromFile(f,K->e);
	zFromFile(f,K->p);
	zFromFile(f,K->q);
	zFromFile(f,K->d);
	return 0;
}
int rsa_shredKey(RSA_KEY* K)
{
	/* clear memory for key. */
	mpz_t* L[5] = {&K->d,&K->e,&K->n,&K->p,&K->q};
	size_t i;
	for (i = 0; i < 5; i++) {
		size_t nLimbs = mpz_size(*L[i]);
		if (nLimbs) {
			memset(mpz_limbs_write(*L[i],nLimbs),0,nLimbs*sizeof(mp_limb_t));
			mpz_clear(*L[i]);
		}
	}
	/* NOTE: a quick look at the gmp source reveals that the return of
	 * mpz_limbs_write is only different than the existing limbs when
	 * the number requested is larger than the allocation (which is
	 * of course larger than mpz_size(X)) */
	return 0;
}
