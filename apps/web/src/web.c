/*------------------------------------------------------------------------------
 MIT License
 
 Copyright (c) 2018 ArgusLab
 
 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:
 
 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.
 
 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 SOFTWARE.
------------------------------------------------------------------------------*/

/*------------------------------------------------------------------------------
    INCLUDES
------------------------------------------------------------------------------*/
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sos.h>
#include <udp.h>
#include <sel4/sel4.h>

#include "BuildingConfig_reader.h"


/*------------------------------------------------------------------------------
    DEFINITIONS & CONSTANTS
------------------------------------------------------------------------------*/

/* Cspace Layout */
#define CNODE_SLOT              (1)
#define SYSCALL_EP_SLOT         (2)

#if !defined(CONFIG_ATTACK)
#define TC_EP_SLOT              (3)
#else
#define THREAD_2_SLOT           (3)
#define TC_EP_SLOT              (4)
#define THREAD_STACK_SIZE 512
#endif

#undef ns
#define ns(x) FLATBUFFERS_WRAP_NAMESPACE(WebProtocol, x)

typedef struct _BuildingData_t {
  float currentTemp;
  int cooling;
  int heating;
  int alarm;
  char platform[16];
} BuildingData_t;

/*------------------------------------------------------------------------------
    VARIABLES
------------------------------------------------------------------------------*/
#if defined(CONFIG_ATTACK)
static uint64_t thread_stack[THREAD_STACK_SIZE];
#endif

/*------------------------------------------------------------------------------
    PROTOTYPES
------------------------------------------------------------------------------*/

/*------------------------------------------------------------------------------
    PROCEEDURES
------------------------------------------------------------------------------*/
#if defined(CONFIG_ATTACK)

void usleep(int usecs) {
    // We need to spin because we do not as yet have a timer interrupt
    while(usecs-- > 0){
         /* Assume 1 GHz clock */
        volatile int i = 1000;
        while(i-- > 0);
        seL4_Yield();
    }
}

void worker_thread(void) {
    uint8_t send_data[4096];
    int len = sizeof(send_data)/sizeof(send_data[0]);
    printf("WEB: Attacker thread started.\n");
    usleep(100);
    printf("#    #   ##    ####  #    # ###### #####  \n" \
           "#    #  #  #  #    # #   #  #      #    # \n" \
           "###### #    # #      ####   #####  #    # \n" \
           "#    # ###### #      #  #   #      #    # \n" \
           "#    # #    # #    # #   #  #      #    # \n" \
           "#    # #    #  ####  #    # ###### #####  \n");
    fflush(stdout);
    usleep(100);

    for(int i = 0; i < sizeof(send_data) / sizeof(uint8_t); i++){
        send_data[i] = 'a';
    }

    while(1) {
        // spoofing C2 AHU fan
        int attack_cap = 10;

        printf("#    #   ##    ####  #    # ###### #####  \n" \
               "#    #  #  #  #    # #   #  #      #    # \n" \
               "###### #    # #      ####   #####  #    # \n" \
               "#    # ###### #      #  #   #      #    # \n" \
               "#    # #    # #    # #   #  #      #    # \n" \
               "#    # #    #  ####  #    # ###### #####  \n");
        fflush(stdout);

        printf("WEB: Attacker attempts to spoof AHU fan...\n");
        len = 10;
        send_packet(decode_ip("192.168.0.201"), 4445, send_data, len);
        // attack_cap is an arbitrary number that represent cap slot index. For the demo to show capability-based security model, this will generate faults
        printf("WEB: Attacker attempts to spoof local temperature control...\n");
        seL4_MessageInfo_t spoof_TC = seL4_MessageInfo_new(0, 0, 0, sizeof(uint8_t));
        seL4_NBSend(attack_cap, spoof_TC);
        attack_cap++;
        usleep(100);
    }
}

#endif

int main(void) {
    static uint8_t recieved_data[4096];
    WebProtocol_BuildingConfig_table_t config;
    int len;
    int err;
    seL4_Word ip;
    seL4_MessageInfo_t msg;
    

    printf("WEB: Started.\n");

//    flatcc_builder_init(&b);
#if defined(CONFIG_ATTACK)
    /* initialize attack worker thread */
    uintptr_t thread_stack_top = (uintptr_t) thread_stack + sizeof(thread_stack);
    seL4_UserContext regs = {0};
    regs.pc = (seL4_Word) worker_thread;
    regs.sp = (seL4_Word) thread_stack_top;
    seL4_TCB_WriteRegisters(THREAD_2_SLOT, seL4_True, 0, 2, &regs);
    seL4_Yield();
#endif

    while(1) {
        len = recv_packet(6666, recieved_data, sizeof(recieved_data)/sizeof(recieved_data[0]), &ip);

        if(!(config = ns(BuildingConfig_as_root(recieved_data)))) {
            printf("WEB: invalid config!\n");
            continue;
        }

        float desiredTemp = ns(BuildingConfig_desiredTemp(config));
        printf("WEB: desiredTemp=%f\n", desiredTemp);

        msg = seL4_MessageInfo_new(0, 0, 0, 2);
        seL4_SetMR(0, 0); //UpdateSetpoint
        seL4_SetMR(1, *(seL4_Word *)&desiredTemp);
        msg = seL4_Call(TC_EP_SLOT, msg);


        msg = seL4_MessageInfo_new(0, 0, 0, 1);
        seL4_SetMR(0, 1); /* GetCurrentTemp */
        msg = seL4_Call(TC_EP_SLOT, msg);

        //TODO eventually figure out how to do this correctly with a cross-compiled flatbuffers

//        ns(BuildingData_start_as_root(&b));
//        ns(BuildingData_currentTemp_add(&b, seL4_GetMR(0)));
//        ns(BuildingData_cooling_add(&b, seL4_GetMR(1)));
//        ns(BuildingData_heating_add(&b, seL4_GetMR(2)));
//        ns(BuildingData_alarm_add(&b, seL4_GetMR(3)));
//        ns(BuildingData_platform_create_str(&b,"seL4"));


//        status.currentTemp = seL4_GetMR(1);

//        printf("WEB: current temp = %f\n", status.currentTemp);
//        ns(BuildingData_end_as_root(&b));
//
//        
//        void *buffer = flatcc_builder_get_direct_buffer(&b, &len);
        
        seL4_Word temp = seL4_GetMR(0);

        BuildingData_t data = {
            .currentTemp = temp,
            .cooling = seL4_GetMR(1),
            .heating = seL4_GetMR(2),
            .alarm = seL4_GetMR(3)
        }; 
        strcpy(data.platform, "seL4");
        memcpy(recieved_data, (void*)&data, sizeof(data)); //TODO: BOO. Don't do this!!!! Hiss look away.
        
        send_packet(ip, 6666, recieved_data, len);


//        flatcc_builder_reset(&b);
    }
    return 0;
}
