//*****************************************************************************
//
// Copyright (C) 2014 Texas Instruments Incorporated - http://www.ti.com/ 
// 
// 
//  Redistribution and use in source and binary forms, with or without 
//  modification, are permitted provided that the following conditions 
//  are met:
//
//    Redistributions of source code must retain the above copyright 
//    notice, this list of conditions and the following disclaimer.
//
//    Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the 
//    documentation and/or other materials provided with the   
//    distribution.
//
//    Neither the name of Texas Instruments Incorporated nor the names of
//    its contributors may be used to endorse or promote products derived
//    from this software without specific prior written permission.
//
//  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
//  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
//  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
//  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT 
//  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
//  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT 
//  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
//  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
//  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
//  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE 
//  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
//*****************************************************************************


//*****************************************************************************
//
// Application Name     -   SSL Demo
// Application Overview -   This is a sample application demonstrating the
//                          use of secure sockets on a CC3200 device.The
//                          application connects to an AP and
//                          tries to establish a secure connection to the
//                          Google server.
// Application Details  -
// docs\examples\CC32xx_SSL_Demo_Application.pdf
// or
// http://processors.wiki.ti.com/index.php/CC32xx_SSL_Demo_Application
//
//*****************************************************************************


//*****************************************************************************
//
//! \addtogroup ssl
//! @{
//
//*****************************************************************************

#include <stdio.h>
#include <stdbool.h>
#include <string.h>

// Simplelink includes
#include "simplelink.h"

//Driverlib includes
#include "hw_types.h"
#include "hw_ints.h"
#include "hw_memmap.h"
#include "hw_common_reg.h"
#include "interrupt.h"
#include "hw_apps_rcm.h"
#include "prcm.h"
#include "rom.h"
#include "rom_map.h"
#include "gpio.h"
#include "timer.h"
#include "spi.h"
#include "prcm.h"
#include "utils.h"
#include "uart.h"

//Common interface includes
#include "pin_mux_config.h"
#include "gpio_if.h"
#include "common.h"
#include "uart_if.h"
#include "timer_if.h"
#include "i2c_if.h"

// Includes Adafruit
#include "Adafruit_GFX.h"
#include "Adafruit_SSD1351.h"
#include "glcdfont.h"
#include "test.h"

#define MAX_URI_SIZE 128
#define URI_SIZE MAX_URI_SIZE + 1


#define APPLICATION_NAME        "SSL"
#define APPLICATION_VERSION     "1.1.1.EEC.Spring2018"
#define SERVER_NAME             "ak4vjnslp06yu-ats.iot.us-east-2.amazonaws.com"
#define GOOGLE_DST_PORT         8443

#define SL_SSL_CA_CERT "/cert/rootCA.der" //starfield class2 rootca (from firefox) // <-- this one works
#define SL_SSL_PRIVATE "/cert/private.der"
#define SL_SSL_CLIENT  "/cert/client.der"

#define BLACK           0x0000
#define BLUE            0x001F
#define GREEN           0x07E0
#define CYAN            0x07FF
#define RED             0xF800
#define MAGENTA         0xF81F
#define YELLOW          0xFFE0
#define WHITE           0xFFFF

#define TR_BUFF_SIZE     100
#define SPI_IF_BIT_RATE  100000
#define MASTER_MSG       "This is CC3200 SPI Master Application\n\r"
//NEED TO UPDATE THIS FOR IT TO WORK!
#define DATE                26    /* Current Date */
#define MONTH               3     /* Month 1-12 */
#define YEAR                2024  /* Current year */
#define HOUR                10    /* Time - hours */
#define MINUTE              39    /* Time - minutes */
#define SECOND              0     /* Time - seconds */

#define POSTHEADER "POST /things/amabel_CC3200_Board/shadow HTTP/1.1\r\n"
#define HOSTHEADER "Host: ak4vjnslp06yu-ats.iot.us-east-2.amazonaws.com\r\n"
#define CHEADER "Connection: Keep-Alive\r\n"
#define CTHEADER "Content-Type: application/json; charset=utf-8\r\n"
#define CLHEADER1 "Content-Length: "
#define CLHEADER2 "\r\n\r\n"

#define DATA0 "{\"state\": {\r\n\"desired\" : {\r\n\"var\" : \"WA!\",\r\n\"Fall_State\": 0\r\n}}}\r\n\r\n"
#define DATA1 "{\"state\": {\"desired\" : {\"var\" : \"WA!\",\"Fall_State\": 1}}}\r\n\r\n"
// Application specific status/error codes
typedef enum{
    // Choosing -0x7D0 to avoid overlap w/ host-driver's error codes
    LAN_CONNECTION_FAILED = -0x7D0,
    INTERNET_CONNECTION_FAILED = LAN_CONNECTION_FAILED - 1,
    DEVICE_NOT_IN_STATION_MODE = INTERNET_CONNECTION_FAILED - 1,

    STATUS_CODE_MAX = -0xBB8
}e_AppStatusCodes;

typedef struct
{
   /* time */
   unsigned long tm_sec;
   unsigned long tm_min;
   unsigned long tm_hour;
   /* date */
   unsigned long tm_day;
   unsigned long tm_mon;
   unsigned long tm_year;
   unsigned long tm_week_day; //not required
   unsigned long tm_year_day; //not required
   unsigned long reserved[3];
}SlDateTime;


//*****************************************************************************
//                 GLOBAL VARIABLES -- Start
//*****************************************************************************
extern void (* const g_pfnVectors[])(void);
static unsigned char g_ucTxBuff[TR_BUFF_SIZE];

volatile unsigned long  g_ulStatus = 0;//SimpleLink Status
unsigned long  g_ulPingPacketsRecv = 0; //Number of Ping Packets received
unsigned long  g_ulGatewayIP = 0; //Network Gateway IP address
unsigned char  g_ucConnectionSSID[SSID_LEN_MAX+1]; //Connection SSID
unsigned char  g_ucConnectionBSSID[BSSID_LEN_MAX]; //Connection BSSID
signed char    *g_Host = SERVER_NAME;
SlDateTime g_time;
#if defined(ccs) || defined(gcc)
extern void (* const g_pfnVectors[])(void);
#endif
#if defined(ewarm)
extern uVectorEntry __vector_table;
#endif
//*****************************************************************************
//                 Fall Detection -- End: df
//*****************************************************************************
volatile unsigned char read_flag;
volatile unsigned char warning = 1;
volatile unsigned char prev_warning;
volatile unsigned char post_flag;

long lRetVal = -1;
unsigned char onboardAddr = 0x18;
unsigned char onboardReg_x = 0x03;
unsigned char onboardReg_y = 0x05;
unsigned char onboardReg_z = 0x07;
unsigned char BUFonboardReg_x;
unsigned char BUFonboardReg_y;
unsigned char BUFonboardReg_z;
int diff;
int prev_average;
unsigned char power_reg = 0x6B;
unsigned char power_mode = 0x00;
unsigned char power_values[] = {0x6B, 0x00};
unsigned char power_reg_result;
unsigned char ucDevAddr = 0x68;

unsigned char acc_conf = 0x1C;
unsigned char gyro_conf = 0x1B;
unsigned char acc_precision = 0x18;
unsigned char gyro_precision = 0x18;
unsigned char acc_values[] = {0x1C, 0x18};
unsigned char gyro_values[] = {0x1B, 0x18};

// Acc
const int data_length = 5;
int actual_length;
unsigned char xAccH = 0x3B;
unsigned char xAccL = 0x3C;
unsigned char yAccH = 0x3D;
unsigned char yAccL = 0x3E;
unsigned char zAccH = 0x3F;
unsigned char zAccL = 0x40;
unsigned char ucRdLen = 1;
unsigned char XAccBufH;
unsigned char XAccBufL;
unsigned char YAccBufH;
unsigned char YAccBufL;
unsigned char ZAccBufH;
unsigned char ZAccBufL;
unsigned short int accX[data_length];
unsigned short int accY[data_length];
unsigned short int accZ[data_length];

//Acc
unsigned char xGyroH = 0x43;
unsigned char xGyroL = 0x44;
unsigned char yGyroH = 0x45;
unsigned char yGyroL = 0x46;
unsigned char zGyroH = 0x47;
unsigned char zGyroL = 0x48;
unsigned char XGyroBufH;
unsigned char XGyroBufL;
unsigned char YGyroBufH;
unsigned char YGyroBufL;
unsigned char ZGyroBufH;
unsigned char ZGyroBufL;
unsigned short int gyroX[data_length];
unsigned short int gyroY[data_length];
unsigned short int gyroZ[data_length];

unsigned char BUFonboardReg_x_list[data_length];
unsigned char BUFonboardReg_y_list[data_length];
unsigned char BUFonboardReg_z_list[data_length];

//****************************************************************************
//                      LOCAL FUNCTION PROTOTYPES
//****************************************************************************
static long WlanConnect();
static int set_time();
static void BoardInit(void);
static long InitializeAppVariables();
static int tls_connect();
static int connectToAccessPoint();
static int http_post(int);

//*****************************************************************************
// SimpleLink Asynchronous Event Handlers -- Start
//*****************************************************************************


//*****************************************************************************
//
//! \brief The Function Handles WLAN Events
//!
//! \param[in]  pWlanEvent - Pointer to WLAN Event Info
//!
//! \return None
//!
//*****************************************************************************
void SimpleLinkWlanEventHandler(SlWlanEvent_t *pWlanEvent) {
    if(!pWlanEvent) {
        return;
    }

    switch(pWlanEvent->Event) {
        case SL_WLAN_CONNECT_EVENT: {
            SET_STATUS_BIT(g_ulStatus, STATUS_BIT_CONNECTION);

            //
            // Information about the connected AP (like name, MAC etc) will be
            // available in 'slWlanConnectAsyncResponse_t'.
            // Applications can use it if required
            //
            //  slWlanConnectAsyncResponse_t *pEventData = NULL;
            // pEventData = &pWlanEvent->EventData.STAandP2PModeWlanConnected;
            //

            // Copy new connection SSID and BSSID to global parameters
            memcpy(g_ucConnectionSSID,pWlanEvent->EventData.
                   STAandP2PModeWlanConnected.ssid_name,
                   pWlanEvent->EventData.STAandP2PModeWlanConnected.ssid_len);
            memcpy(g_ucConnectionBSSID,
                   pWlanEvent->EventData.STAandP2PModeWlanConnected.bssid,
                   SL_BSSID_LENGTH);

            UART_PRINT("[WLAN EVENT] STA Connected to the AP: %s , "
                       "BSSID: %x:%x:%x:%x:%x:%x\n\r",
                       g_ucConnectionSSID,g_ucConnectionBSSID[0],
                       g_ucConnectionBSSID[1],g_ucConnectionBSSID[2],
                       g_ucConnectionBSSID[3],g_ucConnectionBSSID[4],
                       g_ucConnectionBSSID[5]);
        }
        break;

        case SL_WLAN_DISCONNECT_EVENT: {
            slWlanConnectAsyncResponse_t*  pEventData = NULL;

            CLR_STATUS_BIT(g_ulStatus, STATUS_BIT_CONNECTION);
            CLR_STATUS_BIT(g_ulStatus, STATUS_BIT_IP_AQUIRED);

            pEventData = &pWlanEvent->EventData.STAandP2PModeDisconnected;

            // If the user has initiated 'Disconnect' request,
            //'reason_code' is SL_USER_INITIATED_DISCONNECTION
            if(SL_USER_INITIATED_DISCONNECTION == pEventData->reason_code) {
                UART_PRINT("[WLAN EVENT]Device disconnected from the AP: %s,"
                    "BSSID: %x:%x:%x:%x:%x:%x on application's request \n\r",
                           g_ucConnectionSSID,g_ucConnectionBSSID[0],
                           g_ucConnectionBSSID[1],g_ucConnectionBSSID[2],
                           g_ucConnectionBSSID[3],g_ucConnectionBSSID[4],
                           g_ucConnectionBSSID[5]);
            }
            else {
                UART_PRINT("[WLAN ERROR]Device disconnected from the AP AP: %s, "
                           "BSSID: %x:%x:%x:%x:%x:%x on an ERROR..!! \n\r",
                           g_ucConnectionSSID,g_ucConnectionBSSID[0],
                           g_ucConnectionBSSID[1],g_ucConnectionBSSID[2],
                           g_ucConnectionBSSID[3],g_ucConnectionBSSID[4],
                           g_ucConnectionBSSID[5]);
            }
            memset(g_ucConnectionSSID,0,sizeof(g_ucConnectionSSID));
            memset(g_ucConnectionBSSID,0,sizeof(g_ucConnectionBSSID));
        }
        break;

        default: {
            UART_PRINT("[WLAN EVENT] Unexpected event [0x%x]\n\r",
                       pWlanEvent->Event);
        }
        break;
    }
}

//*****************************************************************************
//
//! \brief This function handles network events such as IP acquisition, IP
//!           leased, IP released etc.
//!
//! \param[in]  pNetAppEvent - Pointer to NetApp Event Info
//!
//! \return None
//!
//*****************************************************************************
void SimpleLinkNetAppEventHandler(SlNetAppEvent_t *pNetAppEvent) {
    if(!pNetAppEvent) {
        return;
    }

    switch(pNetAppEvent->Event) {
        case SL_NETAPP_IPV4_IPACQUIRED_EVENT: {
            SlIpV4AcquiredAsync_t *pEventData = NULL;

            SET_STATUS_BIT(g_ulStatus, STATUS_BIT_IP_AQUIRED);

            //Ip Acquired Event Data
            pEventData = &pNetAppEvent->EventData.ipAcquiredV4;

            //Gateway IP address
            g_ulGatewayIP = pEventData->gateway;

            UART_PRINT("[NETAPP EVENT] IP Acquired: IP=%d.%d.%d.%d , "
                       "Gateway=%d.%d.%d.%d\n\r",
            SL_IPV4_BYTE(pNetAppEvent->EventData.ipAcquiredV4.ip,3),
            SL_IPV4_BYTE(pNetAppEvent->EventData.ipAcquiredV4.ip,2),
            SL_IPV4_BYTE(pNetAppEvent->EventData.ipAcquiredV4.ip,1),
            SL_IPV4_BYTE(pNetAppEvent->EventData.ipAcquiredV4.ip,0),
            SL_IPV4_BYTE(pNetAppEvent->EventData.ipAcquiredV4.gateway,3),
            SL_IPV4_BYTE(pNetAppEvent->EventData.ipAcquiredV4.gateway,2),
            SL_IPV4_BYTE(pNetAppEvent->EventData.ipAcquiredV4.gateway,1),
            SL_IPV4_BYTE(pNetAppEvent->EventData.ipAcquiredV4.gateway,0));
        }
        break;

        default: {
            UART_PRINT("[NETAPP EVENT] Unexpected event [0x%x] \n\r",
                       pNetAppEvent->Event);
        }
        break;
    }
}


//*****************************************************************************
//
//! \brief This function handles HTTP server events
//!
//! \param[in]  pServerEvent - Contains the relevant event information
//! \param[in]    pServerResponse - Should be filled by the user with the
//!                                      relevant response information
//!
//! \return None
//!
//****************************************************************************
void SimpleLinkHttpServerCallback(SlHttpServerEvent_t *pHttpEvent, SlHttpServerResponse_t *pHttpResponse) {
    // Unused in this application
}

//*****************************************************************************
//
//! \brief This function handles General Events
//!
//! \param[in]     pDevEvent - Pointer to General Event Info
//!
//! \return None
//!
//*****************************************************************************
void SimpleLinkGeneralEventHandler(SlDeviceEvent_t *pDevEvent) {
    if(!pDevEvent) {
        return;
    }

    //
    // Most of the general errors are not FATAL are are to be handled
    // appropriately by the application
    //
    UART_PRINT("[GENERAL EVENT] - ID=[%d] Sender=[%d]\n\n",
               pDevEvent->EventData.deviceEvent.status,
               pDevEvent->EventData.deviceEvent.sender);
}


//*****************************************************************************
//
//! This function handles socket events indication
//!
//! \param[in]      pSock - Pointer to Socket Event Info
//!
//! \return None
//!
//*****************************************************************************
void SimpleLinkSockEventHandler(SlSockEvent_t *pSock) {
    if(!pSock) {
        return;
    }

    switch( pSock->Event ) {
        case SL_SOCKET_TX_FAILED_EVENT:
            switch( pSock->socketAsyncEvent.SockTxFailData.status) {
                case SL_ECLOSE: 
                    UART_PRINT("[SOCK ERROR] - close socket (%d) operation "
                                "failed to transmit all queued packets\n\n", 
                                    pSock->socketAsyncEvent.SockTxFailData.sd);
                    break;
                default: 
                    UART_PRINT("[SOCK ERROR] - TX FAILED  :  socket %d , reason "
                                "(%d) \n\n",
                                pSock->socketAsyncEvent.SockTxFailData.sd, pSock->socketAsyncEvent.SockTxFailData.status);
                  break;
            }
            break;

        default:
            UART_PRINT("[SOCK EVENT] - Unexpected Event [%x0x]\n\n",pSock->Event);
          break;
    }
}


//*****************************************************************************
// SimpleLink Asynchronous Event Handlers -- End breadcrumb: s18_df
//*****************************************************************************


//*****************************************************************************
//
//! \brief This function initializes the application variables
//!
//! \param    0 on success else error code
//!
//! \return None
//!
//*****************************************************************************
static long InitializeAppVariables() {
    g_ulStatus = 0;
    g_ulGatewayIP = 0;
    g_Host = SERVER_NAME;
    memset(g_ucConnectionSSID,0,sizeof(g_ucConnectionSSID));
    memset(g_ucConnectionBSSID,0,sizeof(g_ucConnectionBSSID));
    return SUCCESS;
}


//*****************************************************************************
//! \brief This function puts the device in its default state. It:
//!           - Set the mode to STATION
//!           - Configures connection policy to Auto and AutoSmartConfig
//!           - Deletes all the stored profiles
//!           - Enables DHCP
//!           - Disables Scan policy
//!           - Sets Tx power to maximum
//!           - Sets power policy to normal
//!           - Unregister mDNS services
//!           - Remove all filters
//!
//! \param   none
//! \return  On success, zero is returned. On error, negative is returned
//*****************************************************************************
static long ConfigureSimpleLinkToDefaultState() {
    SlVersionFull   ver = {0};
    _WlanRxFilterOperationCommandBuff_t  RxFilterIdMask = {0};

    unsigned char ucVal = 1;
    unsigned char ucConfigOpt = 0;
    unsigned char ucConfigLen = 0;
    unsigned char ucPower = 0;

    long lRetVal = -1;
    long lMode = -1;

    lMode = sl_Start(0, 0, 0);
    ASSERT_ON_ERROR(lMode);

    // If the device is not in station-mode, try configuring it in station-mode 
    if (ROLE_STA != lMode) {
        if (ROLE_AP == lMode) {
            // If the device is in AP mode, we need to wait for this event 
            // before doing anything 
            while(!IS_IP_ACQUIRED(g_ulStatus)) {
#ifndef SL_PLATFORM_MULTI_THREADED
              _SlNonOsMainLoopTask(); 
#endif
            }
        }

        // Switch to STA role and restart 
        lRetVal = sl_WlanSetMode(ROLE_STA);
        ASSERT_ON_ERROR(lRetVal);

        lRetVal = sl_Stop(0xFF);
        ASSERT_ON_ERROR(lRetVal);

        lRetVal = sl_Start(0, 0, 0);
        ASSERT_ON_ERROR(lRetVal);

        // Check if the device is in station again 
        if (ROLE_STA != lRetVal) {
            // We don't want to proceed if the device is not coming up in STA-mode 
            return DEVICE_NOT_IN_STATION_MODE;
        }
    }
    
    // Get the device's version-information
    ucConfigOpt = SL_DEVICE_GENERAL_VERSION;
    ucConfigLen = sizeof(ver);
    lRetVal = sl_DevGet(SL_DEVICE_GENERAL_CONFIGURATION, &ucConfigOpt, 
                                &ucConfigLen, (unsigned char *)(&ver));
    ASSERT_ON_ERROR(lRetVal);
    
    UART_PRINT("Host Driver Version: %s\n\r",SL_DRIVER_VERSION);
    UART_PRINT("Build Version %d.%d.%d.%d.31.%d.%d.%d.%d.%d.%d.%d.%d\n\r",
    ver.NwpVersion[0],ver.NwpVersion[1],ver.NwpVersion[2],ver.NwpVersion[3],
    ver.ChipFwAndPhyVersion.FwVersion[0],ver.ChipFwAndPhyVersion.FwVersion[1],
    ver.ChipFwAndPhyVersion.FwVersion[2],ver.ChipFwAndPhyVersion.FwVersion[3],
    ver.ChipFwAndPhyVersion.PhyVersion[0],ver.ChipFwAndPhyVersion.PhyVersion[1],
    ver.ChipFwAndPhyVersion.PhyVersion[2],ver.ChipFwAndPhyVersion.PhyVersion[3]);

    // Set connection policy to Auto + SmartConfig 
    //      (Device's default connection policy)
    lRetVal = sl_WlanPolicySet(SL_POLICY_CONNECTION, 
                                SL_CONNECTION_POLICY(1, 0, 0, 0, 1), NULL, 0);
    ASSERT_ON_ERROR(lRetVal);

    // Remove all profiles
    lRetVal = sl_WlanProfileDel(0xFF);
    ASSERT_ON_ERROR(lRetVal);

    

    //
    // Device in station-mode. Disconnect previous connection if any
    // The function returns 0 if 'Disconnected done', negative number if already
    // disconnected Wait for 'disconnection' event if 0 is returned, Ignore 
    // other return-codes
    //
    lRetVal = sl_WlanDisconnect();
    if(0 == lRetVal) {
        // Wait
        while(IS_CONNECTED(g_ulStatus)) {
#ifndef SL_PLATFORM_MULTI_THREADED
              _SlNonOsMainLoopTask(); 
#endif
        }
    }

    // Enable DHCP client
    lRetVal = sl_NetCfgSet(SL_IPV4_STA_P2P_CL_DHCP_ENABLE,1,1,&ucVal);
    ASSERT_ON_ERROR(lRetVal);

    // Disable scan
    ucConfigOpt = SL_SCAN_POLICY(0);
    lRetVal = sl_WlanPolicySet(SL_POLICY_SCAN , ucConfigOpt, NULL, 0);
    ASSERT_ON_ERROR(lRetVal);

    // Set Tx power level for station mode
    // Number between 0-15, as dB offset from max power - 0 will set max power
    ucPower = 0;
    lRetVal = sl_WlanSet(SL_WLAN_CFG_GENERAL_PARAM_ID, 
            WLAN_GENERAL_PARAM_OPT_STA_TX_POWER, 1, (unsigned char *)&ucPower);
    ASSERT_ON_ERROR(lRetVal);

    // Set PM policy to normal
    lRetVal = sl_WlanPolicySet(SL_POLICY_PM , SL_NORMAL_POLICY, NULL, 0);
    ASSERT_ON_ERROR(lRetVal);

    // Unregister mDNS services
    lRetVal = sl_NetAppMDNSUnRegisterService(0, 0);
    ASSERT_ON_ERROR(lRetVal);

    // Remove  all 64 filters (8*8)
    memset(RxFilterIdMask.FilterIdMask, 0xFF, 8);
    lRetVal = sl_WlanRxFilterSet(SL_REMOVE_RX_FILTER, (_u8 *)&RxFilterIdMask,
                       sizeof(_WlanRxFilterOperationCommandBuff_t));
    ASSERT_ON_ERROR(lRetVal);

    lRetVal = sl_Stop(SL_STOP_TIMEOUT);
    ASSERT_ON_ERROR(lRetVal);

    InitializeAppVariables();
    
    return lRetVal; // Success
}


//*****************************************************************************
//
//! Board Initialization & Configuration
//!
//! \param  None
//!
//! \return None
//
//*****************************************************************************
static void BoardInit(void) {
/* In case of TI-RTOS vector table is initialize by OS itself */
#ifndef USE_TIRTOS
  //
  // Set vector table base
  //
#if defined(ccs)
    MAP_IntVTableBaseSet((unsigned long)&g_pfnVectors[0]);
#endif
#if defined(ewarm)
    MAP_IntVTableBaseSet((unsigned long)&__vector_table);
#endif
#endif
    //
    // Enable Processor
    //
    MAP_IntMasterEnable();
    MAP_IntEnable(FAULT_SYSTICK);

    PRCMCC3200MCUInit();
}


//****************************************************************************
//
//! \brief Connecting to a WLAN Accesspoint
//!
//!  This function connects to the required AP (SSID_NAME) with Security
//!  parameters specified in te form of macros at the top of this file
//!
//! \param  None
//!
//! \return  0 on success else error code
//!
//! \warning    If the WLAN connection fails or we don't aquire an IP
//!            address, It will be stuck in this function forever.
//
//****************************************************************************
static long WlanConnect() {
    SlSecParams_t secParams = {0};
    long lRetVal = 0;

    secParams.Key = SECURITY_KEY;
    secParams.KeyLen = strlen(SECURITY_KEY);
    secParams.Type = SECURITY_TYPE;

    UART_PRINT("Attempting connection to access point: ");
    UART_PRINT(SSID_NAME);
    UART_PRINT("... ...");
    lRetVal = sl_WlanConnect(SSID_NAME, strlen(SSID_NAME), 0, &secParams, 0);
    ASSERT_ON_ERROR(lRetVal);

    UART_PRINT(" Connected!!!\n\r");


    // Wait for WLAN Event
    while((!IS_CONNECTED(g_ulStatus)) || (!IS_IP_ACQUIRED(g_ulStatus))) {
        // Toggle LEDs to Indicate Connection Progress
        _SlNonOsMainLoopTask();
        GPIO_IF_LedOff(MCU_IP_ALLOC_IND);
        MAP_UtilsDelay(800000);
        _SlNonOsMainLoopTask();
        GPIO_IF_LedOn(MCU_IP_ALLOC_IND);
        MAP_UtilsDelay(800000);
    }

    return SUCCESS;

}




long printErrConvenience(char * msg, long retVal) {
    UART_PRINT(msg);
    GPIO_IF_LedOn(MCU_RED_LED_GPIO);
    return retVal;
}


//*****************************************************************************
//
//! This function updates the date and time of CC3200.
//!
//! \param None
//!
//! \return
//!     0 for success, negative otherwise
//!
//*****************************************************************************

static int set_time() {
    long retVal;

    g_time.tm_day = DATE;
    g_time.tm_mon = MONTH;
    g_time.tm_year = YEAR;
    g_time.tm_sec = HOUR;
    g_time.tm_hour = MINUTE;
    g_time.tm_min = SECOND;

    retVal = sl_DevSet(SL_DEVICE_GENERAL_CONFIGURATION,
                          SL_DEVICE_GENERAL_CONFIGURATION_DATE_TIME,
                          sizeof(SlDateTime),(unsigned char *)(&g_time));

    ASSERT_ON_ERROR(retVal);
    return SUCCESS;
}

//*****************************************************************************
//
//! This function demonstrates how certificate can be used with SSL.
//! The procedure includes the following steps:
//! 1) connect to an open AP
//! 2) get the server name via a DNS request
//! 3) define all socket options and point to the CA certificate
//! 4) connect to the server via TCP
//!
//! \param None
//!
//! \return  0 on success else error code
//! \return  LED1 is turned solid in case of success
//!    LED2 is turned solid in case of failure
//!
//*****************************************************************************
static int tls_connect() {
    SlSockAddrIn_t    Addr;
    int    iAddrSize;
    unsigned char    ucMethod = SL_SO_SEC_METHOD_TLSV1_2;
    unsigned int uiIP;
//    unsigned int uiCipher = SL_SEC_MASK_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA;
    unsigned int uiCipher = SL_SEC_MASK_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256;
// SL_SEC_MASK_SSL_RSA_WITH_RC4_128_SHA
// SL_SEC_MASK_SSL_RSA_WITH_RC4_128_MD5
// SL_SEC_MASK_TLS_RSA_WITH_AES_256_CBC_SHA
// SL_SEC_MASK_TLS_DHE_RSA_WITH_AES_256_CBC_SHA
// SL_SEC_MASK_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
// SL_SEC_MASK_TLS_ECDHE_RSA_WITH_RC4_128_SHA
// SL_SEC_MASK_TLS_RSA_WITH_AES_128_CBC_SHA256
// SL_SEC_MASK_TLS_RSA_WITH_AES_256_CBC_SHA256
// SL_SEC_MASK_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
// SL_SEC_MASK_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 // does not work (-340, handshake fails)
    long lRetVal = -1;
    int iSockID;

    lRetVal = sl_NetAppDnsGetHostByName(g_Host, strlen((const char *)g_Host),
                                    (unsigned long*)&uiIP, SL_AF_INET);

    if(lRetVal < 0) {
        return printErrConvenience("Device couldn't retrieve the host name \n\r", lRetVal);
    }

    Addr.sin_family = SL_AF_INET;
    Addr.sin_port = sl_Htons(GOOGLE_DST_PORT);
    Addr.sin_addr.s_addr = sl_Htonl(uiIP);
    iAddrSize = sizeof(SlSockAddrIn_t);
    //
    // opens a secure socket
    //
    iSockID = sl_Socket(SL_AF_INET,SL_SOCK_STREAM, SL_SEC_SOCKET);
    if( iSockID < 0 ) {
        return printErrConvenience("Device unable to create secure socket \n\r", lRetVal);
    }

    //
    // configure the socket as TLS1.2
    //
    lRetVal = sl_SetSockOpt(iSockID, SL_SOL_SOCKET, SL_SO_SECMETHOD, &ucMethod,\
                               sizeof(ucMethod));
    if(lRetVal < 0) {
        return printErrConvenience("Device couldn't set socket options \n\r", lRetVal);
    }
    //
    //configure the socket as ECDHE RSA WITH AES256 CBC SHA
    //
    lRetVal = sl_SetSockOpt(iSockID, SL_SOL_SOCKET, SL_SO_SECURE_MASK, &uiCipher,\
                           sizeof(uiCipher));
    if(lRetVal < 0) {
        return printErrConvenience("Device couldn't set socket options \n\r", lRetVal);
    }



/////////////////////////////////
// START: COMMENT THIS OUT IF DISABLING SERVER VERIFICATION
    //
    //configure the socket with CA certificate - for server verification
    //
    lRetVal = sl_SetSockOpt(iSockID, SL_SOL_SOCKET, \
                           SL_SO_SECURE_FILES_CA_FILE_NAME, \
                           SL_SSL_CA_CERT, \
                           strlen(SL_SSL_CA_CERT));

    if(lRetVal < 0) {
        return printErrConvenience("Device couldn't set socket options \n\r", lRetVal);
    }
// END: COMMENT THIS OUT IF DISABLING SERVER VERIFICATION
/////////////////////////////////


    //configure the socket with Client Certificate - for server verification
    //
    lRetVal = sl_SetSockOpt(iSockID, SL_SOL_SOCKET, \
                SL_SO_SECURE_FILES_CERTIFICATE_FILE_NAME, \
                                    SL_SSL_CLIENT, \
                           strlen(SL_SSL_CLIENT));

    if(lRetVal < 0) {
        return printErrConvenience("Device couldn't set socket options \n\r", lRetVal);
    }

    //configure the socket with Private Key - for server verification
    //
    lRetVal = sl_SetSockOpt(iSockID, SL_SOL_SOCKET, \
            SL_SO_SECURE_FILES_PRIVATE_KEY_FILE_NAME, \
            SL_SSL_PRIVATE, \
                           strlen(SL_SSL_PRIVATE));

    if(lRetVal < 0) {
        return printErrConvenience("Device couldn't set socket options \n\r", lRetVal);
    }


    /* connect to the peer device - Google server */
    lRetVal = sl_Connect(iSockID, ( SlSockAddr_t *)&Addr, iAddrSize);

    if(lRetVal >= 0) {
        UART_PRINT("Device has connected to the website:");
        UART_PRINT(SERVER_NAME);
        UART_PRINT("\n\r");
    }
    else if(lRetVal == SL_ESECSNOVERIFY) {
        UART_PRINT("Device has connected to the website (UNVERIFIED):");
        UART_PRINT(SERVER_NAME);
        UART_PRINT("\n\r");
    }
    else if(lRetVal < 0) {
        UART_PRINT("Device couldn't connect to server:");
        UART_PRINT(SERVER_NAME);
        UART_PRINT("\n\r");
        return printErrConvenience("Device couldn't connect to server \n\r", lRetVal);
    }

    GPIO_IF_LedOff(MCU_RED_LED_GPIO);
    GPIO_IF_LedOn(MCU_GREEN_LED_GPIO);
    return iSockID;
}



int connectToAccessPoint() {
    long lRetVal = -1;
    GPIO_IF_LedConfigure(LED1|LED3);

    GPIO_IF_LedOff(MCU_RED_LED_GPIO);
    GPIO_IF_LedOff(MCU_GREEN_LED_GPIO);

    lRetVal = InitializeAppVariables();
    ASSERT_ON_ERROR(lRetVal);

    //
    // Following function configure the device to default state by cleaning
    // the persistent settings stored in NVMEM (viz. connection profiles &
    // policies, power policy etc)
    //
    // Applications may choose to skip this step if the developer is sure
    // that the device is in its default state at start of applicaton
    //
    // Note that all profiles and persistent settings that were done on the
    // device will be lost
    //
    lRetVal = ConfigureSimpleLinkToDefaultState();
    if(lRetVal < 0) {
      if (DEVICE_NOT_IN_STATION_MODE == lRetVal)
          UART_PRINT("Failed to configure the device in its default state \n\r");

      return lRetVal;
    }

    UART_PRINT("Device is configured in default state \n\r");

    CLR_STATUS_BIT_ALL(g_ulStatus);

    ///
    // Assumption is that the device is configured in station mode already
    // and it is in its default state
    //
    UART_PRINT("Opening sl_start\n\r");
    lRetVal = sl_Start(0, 0, 0);
    if (lRetVal < 0 || ROLE_STA != lRetVal) {
        UART_PRINT("Failed to start the device \n\r");
        return lRetVal;
    }

    UART_PRINT("Device started as STATION \n\r");

    //
    //Connecting to WLAN AP
    //
    lRetVal = WlanConnect();
    if(lRetVal < 0) {
        UART_PRINT("Failed to establish connection w/ an AP \n\r");
        GPIO_IF_LedOn(MCU_RED_LED_GPIO);
        return lRetVal;
    }

    UART_PRINT("Connection established w/ AP and IP is aquired \n\r");
    return 0;
}

//*****************************************************************
//For Fall detection
//*****************************************************************

void TimerA0IntHandler(void){
    Timer_IF_InterruptClear(TIMERA0_BASE);
    read_flag = 1; // marking every 0.5 ms interval
}

void Read_Value(void){
    actual_length++;
    // Set up here. Sometimes loose wire cause it to restart and lost 6B value. Always reset here
    I2C_IF_Write(ucDevAddr, power_values, 2, 1);
    I2C_IF_Write(ucDevAddr, acc_values, 2, 1);
    I2C_IF_Write(ucDevAddr, gyro_values, 2, 1);

    // Make sure it's still 0
    I2C_IF_Write(ucDevAddr, &power_reg, 1, 0);
    I2C_IF_Read(ucDevAddr, &power_reg_result, ucRdLen);
    UART_PRINT("Reg is: %d\r\n", power_reg_result);

    //-------------------------------------------------------------
    // Read for ACC
    I2C_IF_Write(ucDevAddr, &xAccH, 1, 0);
    I2C_IF_Read(ucDevAddr, &XAccBufH, ucRdLen);
    I2C_IF_Write(ucDevAddr, &xAccL, 1, 0);
    I2C_IF_Read(ucDevAddr, &XAccBufL, ucRdLen);
    UART_PRINT("X is: %d, 0x%x\r\n", XAccBufH, XAccBufH);
    UART_PRINT("X is: %d, 0x%x\r\n", XAccBufH, XAccBufH);

    I2C_IF_Write(ucDevAddr, &yAccH, 1, 0);
    I2C_IF_Read(ucDevAddr, &YAccBufH, ucRdLen);
    I2C_IF_Write(ucDevAddr, &yAccL, 1, 0);
    I2C_IF_Read(ucDevAddr, &YAccBufL, ucRdLen);

    I2C_IF_Write(ucDevAddr, &zAccH, 1, 0);
    I2C_IF_Read(ucDevAddr, &ZAccBufH, ucRdLen);
    I2C_IF_Write(ucDevAddr, &zAccL, 1, 0);
    I2C_IF_Read(ucDevAddr, &ZAccBufL, ucRdLen);

    //Combine them
    accX[actual_length] = ((XAccBufH << 8) | XAccBufL);
    accY[actual_length] = ((YAccBufH << 8) | YAccBufL);
    accZ[actual_length] = ((ZAccBufH << 8) | ZAccBufL);

//                UART_PRINT("Print from ACC here: \r\n");
//                UART_PRINT("X is: %d, 0x%x\r\n", accX[i], accX[i]);
//                UART_PRINT("Y is: %d, 0x%x\r\n", accY[i], accY[i]);
//                UART_PRINT("Z is: %d, 0x%x\r\n \r\n", accZ[i], accZ[i]);

    //Read from off board Gyro
    I2C_IF_Write(ucDevAddr, &xGyroH, 1, 0);
    I2C_IF_Read(ucDevAddr, &XGyroBufH, ucRdLen);
    I2C_IF_Write(ucDevAddr, &xGyroL, 1, 0);
    I2C_IF_Read(ucDevAddr, &XGyroBufL, ucRdLen);

    I2C_IF_Write(ucDevAddr, &yGyroH, 1, 0);
    I2C_IF_Read(ucDevAddr, &YGyroBufH, ucRdLen);
    I2C_IF_Write(ucDevAddr, &yGyroL, 1, 0);
    I2C_IF_Read(ucDevAddr, &YGyroBufL, ucRdLen);

    I2C_IF_Write(ucDevAddr, &zGyroH, 1, 0);
    I2C_IF_Read(ucDevAddr, &ZGyroBufH, ucRdLen);
    I2C_IF_Write(ucDevAddr, &zGyroL, 1, 0);
    I2C_IF_Read(ucDevAddr, &ZGyroBufL, ucRdLen);

    //Combine them
    gyroX[actual_length] = ((XGyroBufH << 8) | XGyroBufL);
    gyroY[actual_length] = ((YGyroBufH << 8) | YGyroBufL);
    gyroZ[actual_length] = ((ZGyroBufH << 8) | ZGyroBufL);

//                UART_PRINT("Print from GYRO here: \r\n");
//                UART_PRINT("X is: %d, 0x%x\r\n", gyroX[i], gyroX[i]);
//                UART_PRINT("Y is: %d, 0x%x\r\n", gyroY[i], gyroY[i]);
//                UART_PRINT("Z is: %d, 0x%x\r\n \r\n", gyroZ[i], gyroZ[i]);

    //Read from on board
    I2C_IF_Write(onboardAddr, &onboardReg_x, 1, 0);
    I2C_IF_Read(onboardAddr, &BUFonboardReg_x, ucRdLen);
    I2C_IF_Write(onboardAddr, &onboardReg_y, 1, 0);
    I2C_IF_Read(onboardAddr, &BUFonboardReg_y, ucRdLen);
    I2C_IF_Write(onboardAddr, &onboardReg_z, 1, 0);
    I2C_IF_Read(onboardAddr, &BUFonboardReg_z, ucRdLen);

    BUFonboardReg_x_list[actual_length] = BUFonboardReg_x;
    BUFonboardReg_y_list[actual_length] = BUFonboardReg_y;
    BUFonboardReg_z_list[actual_length] = BUFonboardReg_z;

    UART_PRINT("Print from ACC on board here: \r\n");
    UART_PRINT("X is: %d, 0x%x\r\n", BUFonboardReg_x, BUFonboardReg_x);
    UART_PRINT("Y is: %d, 0x%x\r\n", BUFonboardReg_y, BUFonboardReg_y);
    UART_PRINT("Z is: %d, 0x%x\r\n \r\n", BUFonboardReg_z, BUFonboardReg_z);
//    diff = BUFonboardReg_z_list[actual_length]-BUFonboardReg_z_list[actual_length-1];
//    if (diff < 0){
//        diff = diff*-1;
//    }
    //UART_PRINT("Z is: %d\r\n", diff);

//    if (diff>50){
//        drawString("Jogging!", 5);
//    }
//    else if (diff>20){
//        drawString("Walking!", 5);
//    }
//    else if (diff < 10){
//        drawString("Still!", 5);
//    }
    //KalmanFilter(3);


//    UART_PRINT("X is:");
//    int i=0;
//    for (i=0; i<data_length; i++){
//        UART_PRINT("%d ", accX[i], accX[i]);
//    }
//    UART_PRINT("\r\n");
//    UART_PRINT("Y is:");
//    for (i=0; i<data_length; i++){
//        UART_PRINT("%d ", accY[i], accY[i]);
//    }
//    UART_PRINT("\r\n");
//    UART_PRINT("Z is:");
//    for (i=0; i<data_length; i++){
//        UART_PRINT("%d ", accZ[i], accZ[i]);
//    }
//    UART_PRINT("\r\n");
//    UART_PRINT("\r\n");
//    // Gyro
//    UART_PRINT("X Gyro is:");
//    for (i=0; i<data_length; i++){
//        UART_PRINT("%d ", gyroX[i], gyroX[i]);
//    }
//    UART_PRINT("\r\n");
//    UART_PRINT("Y Gyro is:");
//    for (i=0; i<data_length; i++){
//        UART_PRINT("%d ", gyroY[i], gyroY[i]);
//    }
//    UART_PRINT("\r\n");
//    UART_PRINT("Z Gyro is:");
//    for (i=0; i<data_length; i++){
//        UART_PRINT("%d ", gyroZ[i], gyroZ[i]);
//    }
//    UART_PRINT("\r\n");
}

void KalmanFilter(float z) {
    // Predict
    float x_hat_minus = x_hat;
    float P_minus = P + Q;

    // Update
    float K = P_minus / (P_minus + R);
    x_hat = x_hat_minus + K * (z - x_hat_minus);
    P = (1 - K) * P_minus;
}

void warning_detect(void){
    //UART_PRINT("In Warning detect\r\n");
    int average = 0;
    int i = 0;
    for (i=0; i<data_length; i++){
        average += BUFonboardReg_z_list[i];
    }
    diff = average - prev_average;
    UART_PRINT("Z is: %d\r\n", diff);
    if (diff>900){
        drawString("Jogging!", 5);
    }
    else if (diff>200){
        drawString("Still!", 5);
    }
    else if (diff < 100){
        drawString("Walking!", 5);
    }
    average = average / data_length;
    if (average > 150){
        warning = 1;
        if (warning != prev_warning){
            UART_PRINT("Warning!!!\r\n");
            drawString("Warning!", 4);
            //Connect the CC3200 to the local access point
            lRetVal = connectToAccessPoint();
            //Set time so that encryption can be used
            lRetVal = set_time();
            if(lRetVal < 0) {
                UART_PRINT("Unable to set time in the device");
                LOOP_FOREVER();
            }
            // Connect to the website with TLS encryption
            lRetVal = tls_connect();
            if(lRetVal < 0) {
                ERR_PRINT(lRetVal);
            }
            http_post(lRetVal);
        }
    }
    else{
        warning = 0;
        if (warning != prev_warning){
            UART_PRINT("All good\r\n");
            drawString("All Good!", 4);
        }
    }
//    if (warning != prev_warning){
//        send_warning_AWS()
//    }
    prev_warning = warning;
    prev_average = average;
}

//void send_warning_AWS(){
//    http_post(lRetVal);
//}
//*****************************************************************************
//
//! Main 
//!
//! \param  none
//!
//! \return None
//!
//*****************************************************************************
void main() {
    int i=0;
    int j=0;
    unsigned long ulStatus;
    //
    // Initialize board configuration
    //
    BoardInit();
    PinMuxConfig();

    InitTerm();
    ClearTerm();
    UART_PRINT("My terminal works!\n\r");

    // SPI CLOCK
     MAP_PRCMPeripheralClkEnable(PRCM_GSPI,PRCM_RUN_MODE_CLK);
     MAP_PRCMPeripheralReset(PRCM_GSPI);
     // Initialize the message
     memcpy(g_ucTxBuff,MASTER_MSG,sizeof(MASTER_MSG));
     // Reset SPI
     MAP_SPIReset(GSPI_BASE);

     // Configure SPI interface
     MAP_SPIConfigSetExpClk(GSPI_BASE,MAP_PRCMPeripheralClockGet(PRCM_GSPI),
                      SPI_IF_BIT_RATE,SPI_MODE_MASTER,SPI_SUB_MODE_0,
                      (SPI_SW_CTRL_CS |
                      SPI_4PIN_MODE |
                      SPI_TURBO_OFF |
                      SPI_CS_ACTIVEHIGH |
                      SPI_WL_8));
     // Enable SPI for communication
     MAP_SPIEnable(GSPI_BASE);

    // Initialize display
    Adafruit_Init();
    fillScreen(BLACK);
    drawString("Terminal Works!", 0);

    //
    // I2C Init
    //
    I2C_IF_Open(I2C_MASTER_MODE_FST);
    UART_PRINT("I2C done\n\r");
    drawString("I2C done!", 1);
    for(i=0; i<10000; i++){
        for(j=0; j<1000; j++){
        }
    }
    I2C_IF_Write(ucDevAddr, power_values, 2, 1);
    I2C_IF_Write(ucDevAddr, acc_values, 2, 1);
    I2C_IF_Write(ucDevAddr, gyro_values, 2, 1);
    UART_PRINT("Reg is: %d\r\n", power_reg_result);
    drawString("Reg is Done", 1);


    //Timer A
    Timer_IF_Init(PRCM_TIMERA0, TIMERA0_BASE, TIMER_CFG_PERIODIC_UP, TIMER_A, 0);
    Timer_IF_IntSetup(TIMERA0_BASE, TIMER_A, TimerA0IntHandler);
    Timer_IF_Stop(TIMERA0_BASE, TIMER_A);
    MAP_TimerLoadSet(TIMERA0_BASE, TIMER_A, 25000);
    UART_PRINT("TIMER A done\n\r");
    drawString("Timer A init", 1);

//    //Connect the CC3200 to the local access point
//    lRetVal = connectToAccessPoint();
//    //Set time so that encryption can be used
//    lRetVal = set_time();
//    if(lRetVal < 0) {
//        UART_PRINT("Unable to set time in the device");
//        LOOP_FOREVER();
//    }
//    // Connect to the website with TLS encryption
//    lRetVal = tls_connect();
//    if(lRetVal < 0) {
//        ERR_PRINT(lRetVal);
//    }
    //http_post(lRetVal);
    //sl_Stop(SL_STOP_TIMEOUT);
    //LOOP_FOREVER();


    MAP_TimerEnable(TIMERA0_BASE, TIMER_A);
    UART_PRINT("Timer A enabled done\n\r");
    drawString("Timer A load, begin read", 1);
    while (1){
        while (read_flag == 0){;}
        if (read_flag){
            Message("Set Read Flag\r\n");
            read_flag = 0;
            Read_Value();
        }
        if (actual_length == data_length){
            actual_length=0;
            warning_detect();
            // Trigger compare here
        }

//        I2C_IF_Write(onboardAddr, &onboardReg_x, 1, 0);
//        I2C_IF_Read(onboardAddr, &BUFonboardReg_x, ucRdLen);
//        I2C_IF_Write(onboardAddr, &onboardReg_y, 1, 0);
//        I2C_IF_Read(onboardAddr, &BUFonboardReg_y, ucRdLen);
//        I2C_IF_Write(onboardAddr, &onboardReg_z, 1, 0);
//        I2C_IF_Read(onboardAddr, &BUFonboardReg_z, ucRdLen);
//        UART_PRINT("Print from ACC on board here: \r\n");
//        UART_PRINT("X is: %d, 0x%x\r\n", BUFonboardReg_x, BUFonboardReg_x);
//        UART_PRINT("Y is: %d, 0x%x\r\n", BUFonboardReg_y, BUFonboardReg_y);
//        UART_PRINT("Z is: %d, 0x%x\r\n \r\n", BUFonboardReg_z, BUFonboardReg_z);
//        if (post_flag==1){
//
//            post_flag = 0;
//        }
    }
}
//*****************************************************************************
//
// Close the Doxygen group.
//! @}
//
//*****************************************************************************

static int http_post(int iTLSSockID){
    char acSendBuff[512];
    char acRecvbuff[1460];
    char cCLLength[200];
    char* pcBufHeaders;
    int lRetVal1 = 0;
    int dataLength1 = strlen(DATA1);
    int dataLength0 = strlen(DATA0);

    pcBufHeaders = acSendBuff;
    strcpy(pcBufHeaders, POSTHEADER);
    pcBufHeaders += strlen(POSTHEADER);
    strcpy(pcBufHeaders, HOSTHEADER);
    pcBufHeaders += strlen(HOSTHEADER);
    strcpy(pcBufHeaders, CHEADER);
    pcBufHeaders += strlen(CHEADER);
    strcpy(pcBufHeaders, "\r\n\r\n");

    strcpy(pcBufHeaders, CTHEADER);
    pcBufHeaders += strlen(CTHEADER);
    strcpy(pcBufHeaders, CLHEADER1);

    pcBufHeaders += strlen(CLHEADER1);
    sprintf(cCLLength, "%d", dataLength1);
//    if (warning == 1){
//        pcBufHeaders += strlen(CLHEADER1);
//        sprintf(cCLLength, "%d", dataLength1);
//    }
//    else if (warning == 0){
//        pcBufHeaders += strlen(CLHEADER1);
//        sprintf(cCLLength, "%d", dataLength0);
//    }

    strcpy(pcBufHeaders, cCLLength);
    pcBufHeaders += strlen(cCLLength);
    strcpy(pcBufHeaders, CLHEADER2);
    pcBufHeaders += strlen(CLHEADER2);

    strcpy(pcBufHeaders, DATA1);
    pcBufHeaders += strlen(DATA1);
//    if (warning == 1){
//        strcpy(pcBufHeaders, DATA1);
//        pcBufHeaders += strlen(DATA1);
//    }
//    else if (warning == 0){
//        strcpy(pcBufHeaders, DATA0);
//        pcBufHeaders += strlen(DATA0);
//    }


    int testDataLength = strlen(pcBufHeaders);

    UART_PRINT(acSendBuff);


    //
    // Send the packet to the server */
    //
    lRetVal1 = sl_Send(iTLSSockID, acSendBuff, strlen(acSendBuff), 0);
    if(lRetVal1 < 0) {
        UART_PRINT("POST failed. Error Number: %i\n\r",lRetVal1);
        sl_Close(iTLSSockID);
        GPIO_IF_LedOn(MCU_RED_LED_GPIO);
        return lRetVal1;
    }
    lRetVal1 = sl_Recv(iTLSSockID, &acRecvbuff[0], sizeof(acRecvbuff), 0);
    if(lRetVal1 < 0) {
        UART_PRINT("Received failed. Error Number: %i\n\r",lRetVal1);
        //sl_Close(iSSLSockID);
        GPIO_IF_LedOn(MCU_RED_LED_GPIO);
           return lRetVal1;
    }
    else {
        acRecvbuff[lRetVal1+1] = '\0';
        UART_PRINT(acRecvbuff);
        UART_PRINT("\n\r\n\r");
    }

    return 0;
}

// Merging Check-list
// [ ] I2C DEMO - acc calculation testing and generate Pinmux
// [ ] SSL
// [ ] SPI

// Notes on 3/11: try to print out all x value(10 list) and see
// To do
// [x] Take a sample every 0.02s with timer A
// [x] Trigger a flag for calculation when 100 sample hits
// [ ] After calculation, update to AWS and display on screen

// [x] Copy the program now -> for test and figure out their relation

// Debugging notes:
