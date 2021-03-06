/*------------------------------------------------------------------------------
    INCLUDES
------------------------------------------------------------------------------*/
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sel4/sel4.h>
#include <semaphore.h>

#include <sos.h>
#include <udp.h>
#include <config.h>

#include <autoconf.h>

#include "rijndael-api-fst.h"
#include "md5.h"

/*------------------------------------------------------------------------------
    DEFINITIONS & CONSTANTS
------------------------------------------------------------------------------*/


/* Cspace Layout */
#define CNODE_SLOT              (1)
#define SYSCALL_EP_SLOT         (2)

#define THREAD_STACK_SIZE 512

#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))

enum {
    SendPacket = 0,
    RecievePacket = 1
};

/*------------------------------------------------------------------------------
    VARIABLES
------------------------------------------------------------------------------*/
static uint64_t thread_stacks[CONFIG_APP_PROXY_MAX_NUM_CLIENTS][THREAD_STACK_SIZE];

static proxy_config_t *config = (proxy_config_t*)CONFIG_ADDRESS; 

keyInstance key_e[CONFIG_APP_PROXY_MAX_NUM_CLIENTS];
keyInstance key_d[CONFIG_APP_PROXY_MAX_NUM_CLIENTS];
cipherInstance cipher_e[CONFIG_APP_PROXY_MAX_NUM_CLIENTS];
cipherInstance cipher_d[CONFIG_APP_PROXY_MAX_NUM_CLIENTS];

/*------------------------------------------------------------------------------
    PROTOTYPES
------------------------------------------------------------------------------*/

/*------------------------------------------------------------------------------
    PROCEEDURES
------------------------------------------------------------------------------*/

void worker_thread(void) {
    static uint8_t hashed_data[(1 << seL4_PageBits)];
    static uint8_t recieved_data[(1 << seL4_PageBits)];
    uint32_t len;
    uint32_t id;
    seL4_Word port;
    seL4_Word ip_address;
    seL4_Word remote_ip_address; //UNUSED
    seL4_MessageInfo_t tag;
    seL4_Word badge;

    /* Infer id based on the IPC buffer location. */
    id = (((seL4_Word)seL4_GetIPCBuffer() - 0xa0000000) >> seL4_PageBits) - 1;
    port = config->clients[id].port;
    ip_address = config->clients[id].ip;

    printf("PROXY: Thread %d Started.\n", id, port);

    while(1) {
        /* wait for request */
        tag = seL4_Wait(config->clients[id].ep_cap, &badge);

        if(seL4_MessageInfo_get_length(tag) < 1) continue;

        switch(seL4_GetMR(0)) {
            case SendPacket:
                len = MIN(sizeof(recieved_data), (seL4_MessageInfo_get_length(tag) - 1)*sizeof(seL4_Word));

                //printf("PROXY: sending packet, len=%i\n", len);
        
                if(config->enable_encryption) {//TODO pack length
                    
                    len = (len % 16 > 0) ? (len/16 + 1)*16 : len; /* normalize to block len */
                    MD5_CTX hash_ctx;
                    MD5_Init(&hash_ctx);
                    MD5_Update(&hash_ctx, (void *)(seL4_GetIPCBuffer()->msg + 1), len);
                    MD5_Final(hashed_data, &hash_ctx);

                    memcpy(hashed_data+16, seL4_GetIPCBuffer()->msg + 1, len);
                    len += 16; /* add hash size */

                    
                    printf("PROXY: Hash=%x%x%x%x len=%i\n",
                                   ((int *)hashed_data)[0],
                                   ((int *)hashed_data)[1],
                                   ((int *)hashed_data)[2],
                                   ((int *)hashed_data)[3], len);

                    len = blockEncrypt(
                            &cipher_e[id],
                            &key_e[id],
                            hashed_data,
                            MAX(128, len*8), /* at least 1 block (128 bits) must be used, sizes in bits */
                            recieved_data)/8; /* Offset by 16 bytes for hash */
                    
                    if(len == 0) {
                        printf("PROXY: encrpytion failed.\n");
                        seL4_Reply(tag);
                        break;
                    }
                } else {
                    memcpy(recieved_data, seL4_GetIPCBuffer()->msg + 1, len);
                }
        
                send_packet(ip_address, port, recieved_data, len);
                seL4_Reply(tag);
                break;
            case RecievePacket:
                while(1) {
                    len = recv_packet(port, recieved_data, sizeof(recieved_data), &remote_ip_address);

                    //printf("PROXY: recieved packet, len=%i\n", len);
        
                    if(config->enable_encryption) {
                        len = blockDecrypt(
                                &cipher_d[id],
                                &key_d[id],
                                recieved_data,
                                MAX(128, len*8), /* at least 1 block (128 bits) must be used, sizes in bits */
                                hashed_data)/8;

                        if(len == 0) {
                            printf("PROXY: decrpytion failed.\n");
                            continue;
                        }

                        printf("PROXY: len=%i\n", len);

                        len -= 16;
                        MD5_CTX hash_ctx;
                        MD5_Init(&hash_ctx);
                        MD5_Update(&hash_ctx, (void *)(hashed_data+16), len);
                        MD5_Final(recieved_data, &hash_ctx); /* use a a temp storage place */
                        

                        if(recieved_data[0] != hashed_data[0] ||
                           recieved_data[1] != hashed_data[1] ||     
                           recieved_data[2] != hashed_data[2] ||     
                           recieved_data[3] != hashed_data[3])
                        {
                            printf("PROXY: HASH COMPARISON FAILED. %x%x%x%x != %x%x%x%x\n",
                                   ((int*)recieved_data)[0],
                                   ((int*)recieved_data)[1],
                                   ((int*)recieved_data)[2],
                                   ((int*)recieved_data)[3],
                                   ((int*)hashed_data)[0],
                                   ((int*)hashed_data)[1],
                                   ((int*)hashed_data)[2],
                                   ((int*)hashed_data)[3]);
                            continue;
                        }
                        memcpy(seL4_GetIPCBuffer()->msg, hashed_data+16, len);      

                    } else {
                        memcpy(seL4_GetIPCBuffer()->msg, recieved_data, len);
                    }
        
                    tag = seL4_MessageInfo_new(0, 0, 0, len); //TODO check for correct size (word size)??
                    seL4_SetTag(tag);
                    seL4_Reply(tag);
                    break;
                }
                break;
            default:
                tag = seL4_MessageInfo_new(0, 0, 0, 0); //TODO check for correct size (word size)??
                seL4_SetTag(tag);
                seL4_Reply(tag);
                break;

        }

    }
}


int main(void) {
    int err;

    printf("PROXY: Started.\n");
    printf("PROXY: Initializing %d threads.\n", config->num_clients);

    for(int i = 0; i < config->num_clients; i++) {
        if(config->enable_encryption) {
    
            err = makeKey(&key_e[i], DIR_ENCRYPT, 256, config->clients[i].psk);
            if(err < 0) {
                printf("makeKey e error: %i\n", err);
            }
        
            err = makeKey(&key_d[i], DIR_DECRYPT, 256, config->clients[i].psk);
            if(err < 0) {
                printf("makeKey d error: %i\n", err);
            }
        
            err = cipherInit(&cipher_e[i], MODE_ECB, config->clients[i].iv);
            if(err < 0) {
                printf("cipherInit e error: %i\n", err);
            }
        
            err = cipherInit(&cipher_d[i], MODE_ECB, config->clients[i].iv);
            if(err < 0) {
                printf("cipherInit d error: %i\n", err);
            }
        }

        uintptr_t thread_stack_top = (uintptr_t)thread_stacks[i] + sizeof(thread_stacks[i]);

        seL4_UserContext regs = {0};
        regs.pc = (seL4_Word)worker_thread;
        regs.sp = (seL4_Word)thread_stack_top;

        seL4_TCB_WriteRegisters(config->clients[i].tcb_cap, seL4_True, 0, 2, &regs); //TODO not sure about this local_cap
        seL4_Yield();
    }


    while(1) seL4_Yield();

    return 0;
}
