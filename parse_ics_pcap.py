import argparse
import glob
import json
import os
import pprint
import sys

import nest_asyncio
import pyshark

from ics.ics_info import ics_info

nest_asyncio.apply()  #解決當在同一個事件迴圈中同時運行多個異步任務時可能出現的問題。

def find_pcap_files(folder_path):
    # 使用 glob 模組找到資料夾中所有的 pcap 檔案
    pcap_files = glob.glob(os.path.join(folder_path, '*'))
    return pcap_files

def filter_packets(input_pcap, pkt_layer, protocol, port_num, display_filter, **kwargs):

    packets = pyshark.FileCapture(input_pcap, display_filter= display_filter)
    
    packet_to_save = []
    pcap_dict = {input_pcap : {}}
    idx = 0
    for packet in packets:
        pkt_data = {}
        # opcua 封包可能會有reassembled的封包, 需要確認 packet.data.tcp_segment 是否存在
        # 其他協定可能也有data這個屬性，但有可能是 COTP reassembled
        reassembled_result = [] 

        if 'TCP' in str(packet.layers):
            pkt_data['L4'] = 'TCP'
            src_port_num = packet.tcp.srcport
            dest_port_num = packet.tcp.dstport
        elif 'UDP' in str(packet.layers):
            pkt_data['L4'] = 'UDP'
            src_port_num = packet.udp.srcport
            dest_port_num = packet.udp.dstport
        
        pkt_data['srcport'] = src_port_num
        pkt_data['destport'] = dest_port_num

        # 判斷封包方向, 依據不同的協定，封包方向的判斷方式不同
        if protocol != 'melsec_communication':
            if dest_port_num == port_num:
                direction = "request"
                pkt_data['direction'] = direction
            else:
                direction = "response"
                pkt_data['direction'] = direction

        protocol_value = packet[protocol]

        if protocol_value and hasattr(protocol_value, 'get_field_by_showname'):
            key_field_obj = protocol_value.get_field_by_showname(kwargs.get('key_field_1'))

            if key_field_obj and protocol == 'opcua':
                if hasattr(packet, 'data'):
                    reassembled_pcap_nums = reassembled_pcap_nums_str = [int(i.show) for i in packet.data.tcp_segment.all_fields]
                    reassembled_result.extend(reassembled_pcap_nums)
                key_field_data = int(key_field_obj.show)
                value_to_convert = hex(key_field_data) # 將 10 進位轉換成 16 進位
                key_field_name_1 = kwargs.get('key_field_name_1')
                dir_and_func = f'{direction},{key_field_name_1}={key_field_data}'
            elif key_field_obj and protocol == 's7comm-plus':
                key_field_data = key_field_obj.show
                value_to_convert = int(key_field_data, 16) # 將 16 進位轉換成 10 進位
                key_field_name_1 = kwargs.get('key_field_name_1')
                dir_and_func = f'{direction},{key_field_name_1}={key_field_data}'
            elif key_field_obj and protocol == 'melsec_communication':                    
                subheader = protocol_value.get_field_by_showname(kwargs.get('subheader_magic')).show
                if subheader == "0x5000":
                    direction = "request"
                    pkt_data['direction'] = direction
                elif subheader == "0xd000":
                    direction = "response"
                    pkt_data['direction'] = direction
                
                key_field_data = key_field_obj.show
                value_to_convert = int(key_field_data, 16) 
                key_field_obj_2 = protocol_value.get_field_by_showname(kwargs.get('key_field_2'))
                key_field_data_2 = key_field_obj_2.show
                value_to_convert_2 = int(key_field_data_2, 16)
                
                key_field_name_1 = kwargs.get('key_field_name_1')
                key_field_name_2 = kwargs.get('key_field_name_2')

                dir_and_func = f'{direction},{key_field_name_1}={key_field_data},{key_field_name_2}={key_field_data_2}'
            
            if dir_and_func not in seen_values: # 避免重複處理相同的封包
                seen_values.add(dir_and_func)

                # 找出封包編號
                packet_value = packet.frame_info # 取得封包資訊
                if packet_value and hasattr(packet_value, 'get_field_by_showname'):
                    frame_value = packet_value.get_field_by_showname("Frame Number")
                    if frame_value:
                        frame_num = frame_value.show
                        # 如果有reassembled的封包，則將reassembled的封包編號加入pkt_data
                        if reassembled_result != []:
                            pkt_data['reassembled'] = reassembled_result
                        pkt_data['frame_num'] = frame_num
                        
                        if protocol == 'opcua' or protocol == 's7comm-plus':
                            pcap_filename_data = f'{direction},{key_field_name_1}={key_field_data},({value_to_convert}).pcap'
                        elif protocol == 'melsec_communication':
                            pcap_filename_data = f'{direction},CommandCode={key_field_data},SubCommandCode={key_field_data_2}(CommandCode={value_to_convert},SubCommandCode={value_to_convert_2}).pcap'
                        
                        pkt_data["pcap_filename_data"] = pcap_filename_data
                        packet_to_save.append(pkt_data)
                        pkt = { idx: pkt_data} 
                        pcap_dict[input_pcap].update(pkt)
                        idx = idx + 1
    ics_pcap_info.update(pcap_dict)

    return packet_to_save

def save_new_pcap(input_pcap, display_filter_str , output_file_str):

    pkts_in_pcap = pyshark.FileCapture(input_pcap, display_filter= display_filter_str, output_file= output_file_str)
    pkts_in_pcap.load_packets()

#-------------------------------------------------------

parser = argparse.ArgumentParser(prog=os.path.basename(sys.argv[0]),description="請使用 Windows 環境執行本程式。並確認對應 dll 檔案是否存在。", epilog="::: 範例 ::: python parse_ics_pcap.py -f ./path/to/pcap -p s7comm-plus -s ./path/to/save/pcap  -j ./path/to/save/json")

input_gp = parser.add_argument_group("::: 輸入相關參數 ::")
input_gp.add_argument("-f", "--folder", type=str, dest='folder_path', help="pcap檔案路徑。")
input_gp.add_argument("-p", "--protocol", type=str, dest='protocol', help="選擇要解析的協定。可以選擇 's7comm-plus', 'opcua', 'melsec_communication'。")

output_gp = parser.add_argument_group("::: 輸出相關參數 ::")
output_gp.add_argument("-s", "--split_directory", type=str, dest='split_dir',  required=False, help="將封包檔分割成單一封包後存入指定目錄，將檔名加上欄位名與值。")
output_gp.add_argument("-j", "--json_file", type=str, dest='json_path',  required=False, help="將封包資訊存成 json 檔案。")

args = parser.parse_args()

#-------------------------------------------------------

folder_path = args.folder_path # 指定要遍歷的資料夾路徑
protocol = args.protocol # 指定要解析的協定

pcap_files = find_pcap_files(folder_path) # 找到所有的 pcap 檔案
output_file = args.split_dir # 指定要存放分割後的 pcap 檔案的資料夾

seen_values = set() # 用來儲存已經處理過的封包

ics_pcap_info = {} # 用來儲存所有封包的資訊

# 確認 output_file 是否存在，若不存在則建立 
if not os.path.exists(output_file):
        os.makedirs(output_file)

for input_pcap in pcap_files:
    
    # 根據不同的協定，過濾封包
    if protocol == 's7comm-plus':
        pcap_info_array = filter_packets(input_pcap, **ics_info['s7comm-plus'])
    elif protocol == 'opcua':
        pcap_info_array = filter_packets(input_pcap, **ics_info['opcua'])
    elif protocol == 'melsec_communication':
        pcap_info_array = filter_packets(input_pcap, **ics_info['melsec_communication'])

    for pkt_data in pcap_info_array: # 將過濾後的封包存成新的 pcap 檔案
        # 確認pkt_data是否有reassembled這個key
        if 'reassembled' in pkt_data:
            reassembled_pcap_nums = pkt_data['reassembled']
            conditions = " or ".join([f"frame.number == {num}" for num in reassembled_pcap_nums])
            display_filter_str = conditions
            print(f"display_filter_str= {display_filter_str}...")
            output_file_str = output_file + pkt_data["pcap_filename_data"] # 指定要存放的檔案名稱
            save_new_pcap(input_pcap, display_filter_str , output_file_str) 
            print(f"Saving {output_file_str}...")
        else:
            display_filter_str = f"frame.number == {pkt_data['frame_num']}"  # 指定要過濾的封包編號
            output_file_str = output_file + pkt_data["pcap_filename_data"] # 指定要存放的檔案名稱
            save_new_pcap(input_pcap, display_filter_str , output_file_str) 
            print(f"Saving {output_file_str}...")

# 確認有 -j 參數時，建立 json 檔案

if args.json_path == None:
    #印出到螢幕上
    pprint.pprint(ics_pcap_info, indent=4, sort_dicts=False)
else:
    #輸出到JSON檔案
    with open(args.json_path,'w') as f:
        print(f'\nWrite JSON contents to "{args.json_path}" ...')
        json.dump(ics_pcap_info, f, indent = 4)
