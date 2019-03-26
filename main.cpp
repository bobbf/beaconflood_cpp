#include <iostream>
#include <unistd.h>
#include <map>
#include <thread>

#include <tins/tins.h>

using namespace std;
using namespace Tins;

void send_Beacon();
void send_probeResp(string srcaddr, string desaddr, string ssid);

void recv_Packet();

int isResponse(const Dot11ProbeRequest &proveReq);

inline int DS_status(const Dot11 &dot11) { return dot11.from_ds() * 2 + dot11.to_ds(); }

void listSSID_initialize(const char *filename);
string mac_generate(string oui);

inline string toHexStream(int num) {
    std::string result;
    std::stringstream temp;

    temp << std::hex << std::setw(6) << std::setfill('0') << num;
    temp >> result;

    return result;
}

map<string, string> listSSID = {};

#define	ISRESP_BROADCAST 1
#define ISRESP_UNICAST  2

std::string interface = "";

int generate_num = 0;

int main(int argc, char *argv[])
{
    if (argc != 3) {
        printf("Usage: %s <interface> <SSID File>\n", argv[0]);
        exit(0);
    }

    interface = argv[1];
    listSSID_initialize(argv[2]);

    clog << "== SSID list ==" << endl;

    for (auto it = listSSID.begin(); it!=listSSID.end(); ++it) {
        clog << it->first << "  " << it->second << endl;
    }

    /* Thread for send beacon */
    thread beaconThread(&send_Beacon);

    /* Thread for recv packet & send probeResp */
    //thread recvThread(&recv_Packet);      temporarily annotation for reduce overhead

    beaconThread.join();
    //recvThread.join();
}

void send_Beacon() {
    SnifferConfiguration config;
    config.set_rfmon(true);
    Sniffer sniffer(interface, config);

    PacketSender sender(interface);

    /* TIM struct */
    Dot11ManagementFrame::tim_type tim;

    tim.dtim_count = 1;
    tim.dtim_period = 3;
    tim.bitmap_control = 0;
    tim.partial_virtual_bitmap.insert(tim.partial_virtual_bitmap.begin(), 0);

    int i= 0;

    while(true) {
        for (map<string, string>::iterator it = listSSID.begin(); it!=listSSID.end(); ++it) {

            RadioTap radiotap;

            Dot11Beacon beacon;

            beacon.addr1(Dot11::BROADCAST);
            beacon.addr2(it->first);
            beacon.addr3(beacon.addr2());

            /* Fixed parameters */
            beacon.interval(100);

            /* Capabilities info struct */
            beacon.capabilities().ess(1);
            beacon.capabilities().ibss(0);

            beacon.capabilities().cf_poll(0);
            beacon.capabilities().cf_poll_req(0);
            beacon.capabilities().qos(0);

            beacon.capabilities().privacy(1);
            beacon.capabilities().short_preamble(0);
            beacon.capabilities().pbcc(0);
            beacon.capabilities().channel_agility(0);
            beacon.capabilities().spectrum_mgmt(0);
            beacon.capabilities().sst(1);

            beacon.capabilities().apsd(0);
            beacon.capabilities().radio_measurement(0);
            beacon.capabilities().dsss_ofdm(0);
            beacon.capabilities().delayed_block_ack(0);
            beacon.capabilities().immediate_block_ack(0);

            /* Tagged parameters */
            beacon.ssid(it->second);
            beacon.supported_rates({ 1.0f, 2.0f, 5.5f, 11.0f, 6, 9, 12, 18 });
            beacon.ds_parameter_set(10);
            beacon.tim(tim);
            beacon.erp_information(0);

            Dot11Beacon::vendor_specific_type vendor;
            vendor.oui = "00:50:f2";
            vendor.data.insert(vendor.data.end(),
            {0x02, 0x01, 0x01, 0x00, 0x00, 0x03, 0xa4, 0x00, 0x00, 0x27, 0xa4,
             0x00, 0x00, 0x42, 0x43, 0x5e, 0x00, 0x62, 0x32, 0x2f, 0x00});

            beacon.vendor_specific(vendor);

            beacon.extended_supported_rates({ 24, 36, 48, 54 });

            beacon.rsn_information(RSNInformation::wpa2_psk());

            radiotap.inner_pdu(beacon);

            sender.send(radiotap);
            usleep(100);

            printf("\rPacket send: %d", ++i);
        }
        usleep(10000);

    }
}

void recv_Packet() {
    Sniffer sniffer(interface, Sniffer::PROMISC);

    int j = 0;

    printf("in recv\n");

    while (true) {
        PDU *packet = sniffer.next_packet();
        const Dot11 &dot11 = packet->rfind_pdu<Dot11>();

        /*
         *  DS Status - Address field contents
         *
         *  To Ds  | From DS | Addr 1 | Addr 2 | Addr 3 | Addr 4
         *    0    |  0      |  DA    | SA     | BSSID  | n/a
         *    0    |  1      |  DA    | BSSID  | SA     | n/a
         *    1    |  0      |  BSSID | SA     | DA     | n/a
         *    1    |  1      |  RA    | TA     | DA     | SA
         */

        switch (DS_status(dot11)) {

        }


        /* Send probe response when received probe request */
        if (dot11.type() == Dot11::MANAGEMENT) {
            if (dot11.subtype() == Dot11::PROBE_REQ) {
                const Dot11ProbeRequest &proveReq = packet->rfind_pdu<Dot11ProbeRequest>();
                switch (isResponse(proveReq)) {
                    case ISRESP_BROADCAST:
                    {
                        for (map<string, string>::iterator it = listSSID.begin(); it!=listSSID.end(); ++it) {
                            send_probeResp(it->first, proveReq.addr2().to_string(), it->second);
                            printf("\r%d", j++);
                            usleep(100);
                        }
                        break;
                    }

                    case ISRESP_UNICAST:
                    {
                        map<string, string>::iterator it = listSSID.find( proveReq.addr1().to_string() );
                        send_probeResp(it->first, proveReq.addr2().to_string(), it->second);
                        break;
                    }

                    default:
                        return;

                }
            }
        }   // end if


    }
}

int isResponse(const Dot11ProbeRequest &proveReq) {
    if (proveReq.addr1() == Dot11::BROADCAST) {
        return ISRESP_BROADCAST;
    }

    else if ( listSSID.find(proveReq.addr1().to_string()) != listSSID.end() ) {
        return ISRESP_UNICAST;
    }

    else
        return 0;
}

void send_probeResp(string srcaddr, string desaddr, string ssid) {
    PacketSender sender(interface);

    RadioTap radiotap;
    Dot11ProbeResponse ProbeResp;

    ProbeResp.addr1(desaddr);

    ProbeResp.ds_parameter_set(8);
    ProbeResp.supported_rates({ 1.0f, 2.0f, 5.5f, 11.0f, 6, 9, 12, 18 });
    ProbeResp.erp_information(0);
    ProbeResp.extended_supported_rates({ 24, 36, 48, 54 });

    ProbeResp.rsn_information(RSNInformation::wpa2_psk());

    ProbeResp.addr2(srcaddr);
    ProbeResp.addr3(ProbeResp.addr2());
    ProbeResp.ssid(ssid);

    radiotap.inner_pdu(ProbeResp);

    sender.send(radiotap);
}

void listSSID_initialize(const char *filename) {
    FILE *fp;
    char str[65535];

    string temp = "";

    if ( (fp = fopen(filename, "r")) == NULL ) {
        perror("fopen error");
        exit(1);
    }

    int buf = 0;

    while ( buf = fread(str, 1, 1, fp) ) {
        if ( strcmp(str, "\n") == 0 ) {
            listSSID.insert( pair<string, string>(mac_generate("00:01:36"), temp) );
            temp = "";
        } else {
            temp.append(str);
        }
    }

    fclose(fp);
}

string mac_generate(string oui) {
    string result = "";

    oui += ':';

    string serial_num;
    serial_num = toHexStream(++generate_num);

    serial_num.insert(2, ":");
    serial_num.insert(5, ":");

    result = oui + serial_num;

    return result;
}
