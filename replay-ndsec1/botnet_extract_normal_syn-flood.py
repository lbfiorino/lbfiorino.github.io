#!/bin/python3

import os
import sys
import errno
import time
import argparse
import subprocess
import threading
import pandas as pd
from datetime import datetime
from pytz import timezone


# Get current dir
absolute_path = os.path.abspath(__file__)
script_name = os.path.basename(__file__)
current_dir = absolute_path[0:-(len(script_name))]

# Parser dos parametros
parser = argparse.ArgumentParser()
parser.add_argument("-t", "--num-threads", dest='numthreads', help="Numero de threads para execucao.", default=50)
parser.add_argument("-s", "--sleep-time", dest='sleeptime', help="Tempo de espera (em segundos) para iniciar novas threads.", default=60)
args = parser.parse_args()
parser.print_help()

print("\nATENCAO:")
print("    > AJUSTAR NUMERO DE THREADS E TEMPO DE ESPERA DE ACORDO COM\n \
     O TAMANHO DO PCAP, NUMERO DE AMOSTRAS E CAPACIDADE DE PROCESSAMENTO.")

# Nome do Dataset
DATASET_NAME = "botnet"
# Arquivo PCAP original
PCAP_FILE = "botnet.pcapng"
# Arquivo PCAP com precisao em milisegungos (para extrair os numeros dos frames, baseado nas amostras do CSV)
PCAP_FILE_TIME_MILLIS = "botnet_timestamp_mod.pcap"
# CSV DATASET
CSV_FILE = "gt_botnet.csv"
# Alvo do trafego
DST_IP = "10.10.10.241"
DST_PORT = "80"
PCAPS_DIR = "pcaps_botnet"

# Numero de Threads
N_THREADS = int(args.numthreads)
# Tempo de espera para iniciar novas Threads
TH_TIME_SLEEP = int(args.sleeptime)
# Retorno dos comandos tshark e merge
CMD_RETURN_CODES = []

# Arquivos para salvar os codigos de retorno dos comandos
freturncodes = None

class Logger(object):
    def __init__(self, logfile):
        self.terminal = sys.stdout
        self.log = open(logfile, "w")

    def write(self, message):
        self.terminal.write(message)
        self.log.write(message)
        self.log.flush()

    def flush(self):
        #this flush method is needed for python 3 compatibility.
        #this handles the flush command by doing nothing.
        #you might want to specify some extra behavior here.
        pass


# # Função para executar tshark - extracao dos numeros dos frames no pcap com precisao em milisegundos
# def run_tshark_frames(CMD, outfile=''):
#     """thread function"""
#     print(f"Running: {CMD}")
#     process = subprocess.Popen(CMD, shell=True, stdout=subprocess.PIPE)
#     process.wait()
#     returncode = process.returncode
#     if returncode != 0:
#         msg = "ERROR Extracting frames "+outfile+". Return Code="+str(returncode)+". Sample = "+str(COUNT)
#     else:
#         msg = "OK Extracting frames "+outfile+". Return Code="+str(returncode)+". Sample = "+str(COUNT)
#     CMD_RETURN_CODES.append(msg)


# # Função para executar tshark - extracao dos pacotes do pcap original
# def run_tshark_packets(CMD, outfile=''):
#     """thread function"""
#     print(f"Running: {CMD}")
#     process = subprocess.Popen(CMD, shell=True, stdout=subprocess.PIPE)
#     process.wait()
#     returncode = process.returncode
#     if returncode != 0:
#         msg = "ERROR Extracting packets. File: "+outfile+". Return Code="+str(returncode)
#     else:
#         msg = "OK Extracting packets. File: "+outfile+". Return Code="+str(returncode)
#     print(msg)
#     CMD_RETURN_CODES.append(msg)



# # Função para executar merge parcial
# def run_merge_part(CMD, outfile=''):
#     print(f"Running: {CMD}")
#     process = subprocess.Popen(CMD, shell=True, stdout=subprocess.PIPE)
#     process.wait()
#     returncode = process.returncode
#     if returncode != 0:
#         msg = "ERROR Merging Part: "+outfile+". Return Code="+str(returncode)
#     else:
#         msg = "OK Merging Part: "+outfile+". Return Code="+str(returncode)
#     print(msg)
#     CMD_RETURN_CODES.append(msg)    


# Função para executar wireshark
def run_wireshark(CMD, outfile='', action=''):
    print(f"Running: {CMD}")
    process = subprocess.Popen(CMD, shell=True, stdout=subprocess.PIPE)
    process.wait()
    returncode = process.returncode
    if returncode != 0:
        msg = "ERROR "+action+": "+outfile+". Return Code="+str(returncode)
    else:
        msg = "OK "+action+": "+outfile+". Return Code="+str(returncode)
    print(msg)
    CMD_RETURN_CODES.append(msg) 


# Extrai pacotes de cada amostra do dataset e faz o merge em um unico pcap.
def Extrai_Pacotes(DATASET_NAME, DATAFRAME, LABEL, PCAP_FILE, DST_IP, DST_PORT):

    # Lista de comandos tshark para extracao dos frames
    TSHARK_FRAMES_CMDS = []
    # Lista de comandos tshark para extracao dos pacotes
    TSHARK_PACKETS_CMDS = []
    # Lista dos aquivos pcap de cada amostra
    PCAP_OUTPUT_FILES = []
    # Lista dos arquivos contendo os frames de cada amostra
    FRAMES_FILE = []
    # Arquivo pcap final
    OUTPUT_PCAP = DATASET_NAME+"_"+LABEL+".pcap"
    COUNT = 0

    # Arquivo para os comandos gerados
    tshark_frames_commands_file_name = DATASET_NAME+"_extract-merge_"+LABEL+"_frames_commands.txt"
    tshark_packets_commands_file_name = DATASET_NAME+"_extract-merge_"+LABEL+"_packets_commands.txt"
    tf_commands_file = open(tshark_frames_commands_file_name, "w")
    tp_commands_file = open(tshark_packets_commands_file_name, "w")

    # Gera comandos do tshark para extrair os numeros dos frames de cada amostra
    for index, item in DATAFRAME.iterrows():

        # Print data/hora do csv
        #print(f"From CSV  ->   start-time: {item['start-time']} - end-time: {item['end-time']}")

        # Remove a ultima casa decimal da data/hora. Datetime é em microsegundos e o csv tem uma casa a mais.
        start_time = item['start-time'][:-1]
        end_time = item['end-time'][:-1]

        # Print data/hora corrigida para microsegundos
        #print(f"Corrigido ->   start-time: {start_time}  - end-time: {start_time}")

        # Cria objeto datetime
        start_time = datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S.%f')
        end_time = datetime.strptime(end_time, '%Y-%m-%d %H:%M:%S.%f')

        # Muda timezone para UTC. Para filtrar com o tshark.
        start_time = start_time.replace(tzinfo=timezone('UTC'))
        end_time = end_time.replace(tzinfo=timezone('UTC'))

        # Convete para timestamp
        start_time_timestamp = datetime.timestamp(start_time)
        end_time_timestamp = datetime.timestamp(end_time)

        #print(f"Timestamp ->   start-time: {start_time_timestamp}              - end-time: {end_time_timestamp}")
        #print("\n")

        SRC_IP = item['srcip']
        SRC_PORT = item['srcport']
        
        # Arquivos para cada amostra do CSV
        OUTFILE = PCAPS_DIR+"/"+DATASET_NAME+"_"+LABEL+"_"+str(COUNT)+".pcap"
        FRAMES_SAMPLE_FILE = PCAPS_DIR+"/"+DATASET_NAME+"_"+LABEL+"_frames_"+str(COUNT)+".txt"
        PCAP_OUTPUT_FILES.append(OUTFILE)      # arquivos pcap de cada amostra
        FRAMES_FILE.append(FRAMES_SAMPLE_FILE) # arquivos com os frame numbers de cada amostra

        # Comando para extrair frame numbers do arquivo pcap com a precisao em milisegundos
        CMD_frames = "tshark -n -T fields -e frame.number -r "+PCAP_FILE_TIME_MILLIS + \
                            " -Y \"(frame.time_epoch>=" + str(start_time_timestamp) + " and frame.time_epoch<=" + str(end_time_timestamp) + \
                            ") and ((ip.src=="+SRC_IP + " and tcp.srcport==" + SRC_PORT + " and ip.dst=="+DST_IP + " and tcp.dstport==" + DST_PORT+") or "+ \
                            "(ip.dst=="+SRC_IP + " and tcp.dstport==" + SRC_PORT + " and ip.src=="+DST_IP + " and tcp.srcport==" + DST_PORT+")  )\" > "+FRAMES_SAMPLE_FILE

        TSHARK_FRAMES_CMDS.append(CMD_frames)

        tf_commands_file.write(CMD_frames+"\n")

        COUNT+=1


    # Threads para extrair os numemos dos frames do pcap com precisao em milisegundos
    threads_frames = []
    c = 0
    for CMD in TSHARK_FRAMES_CMDS:
        outfile = CMD.split()[-1]
        t = threading.Thread(target=run_wireshark, args=(CMD, outfile, "Extracting Frames"))
        threads_frames.append(t)
        t.start()
        c+=1
        if (c==N_THREADS):
            print('\nAguardando algumas threads terminarem...')
            time.sleep(TH_TIME_SLEEP)
            c = 0

    # Aguarda todas as threads dos frames terminarem
    for th in threads_frames:
        th.join()

    # print(FRAMES_FILE)
    # print(PCAP_OUTPUT_FILES)

    # Le cada arquivo de frames e para gerar o comando de extracao dos pacotes
    for i, f in enumerate(FRAMES_FILE):
        ff = open(f, "r")
        frame_list = ff.read().splitlines()
        # Cria string com argumentos
        field = "frame.number=="
        frame_list = [field + item for item in frame_list] # Adiciona field para da frame
        ARG_FRAMES = " or ".join(frame_list) # Cria a string para o filtro

        # Comando para extrair pacotes do pcap origigal a partir dos frame numbers extraidos anteriormente
        CMD_packets = "tshark -n -F pcap -r "+PCAP_FILE + \
                " -Y \""+ARG_FRAMES+"\" -w "+PCAP_OUTPUT_FILES[i]

        TSHARK_PACKETS_CMDS.append(CMD_packets)
        tp_commands_file.write(CMD_packets+"\n")


    # Threads para extrair pacotes do pcap para cada amostra do csv
    threads_packets = []
    c = 0
    for CMD in TSHARK_PACKETS_CMDS:
        outfile = CMD.split()[-1]
        t = threading.Thread(target=run_wireshark, args=(CMD, outfile, "Extracting Packets"))
        threads_packets.append(t)
        t.start()
        c+=1
        if (c==N_THREADS):
            print('Aguardando algumas threads terminarem...')
            time.sleep(TH_TIME_SLEEP)
            c = 0

    # Aguarda todas as threads dos pacotes terminarem
    for th in threads_packets:
        th.join()


    # Divide o merge em partes. Conjuntos de 500 arquivos.
    nfiles = 500
    fparts = [PCAP_OUTPUT_FILES[i:i + nfiles] for i in range(0, len(PCAP_OUTPUT_FILES), nfiles)]  

    # Nomes dos arquivos pcap para merce parcial
    merge_parts = []
    # String com a lista de aquivos de cada parte para o merge parcial
    arg_files_part = ""
    # Lista de arg_files_part
    argfiles_merge = []

    # Gera as partes o merge
    for i, p in enumerate(fparts):
        arg_files_part = ""
        merge_parts.append(DATASET_NAME+"_"+LABEL+"_part"+str(i)+'.pcap')
        for filename in p:
            arg_files_part = arg_files_part+filename+" "
        
        argfiles_merge.append(arg_files_part)
    
    # print("\n\n")
    # print(merge_parts)
    # print(arg_files_part)
    # print(argfiles_merge)

    print("\n")
    #Faz o merge de cada conjunto de 500 arquivos    
    for i in range(len(merge_parts)):
        CMD = "mergecap -F pcap -w "+merge_parts[i]+" "+argfiles_merge[i]
        #print(CMD)
        run_wireshark(CMD=CMD, outfile=merge_parts[i], action="Merging Part")
        tp_commands_file.write(CMD+"\n")

    print("\n")


    # Faz o MERGE FINAL com as partes
    merge_files = ""   
    for part in merge_parts:
        merge_files = merge_files+str(part)+" " 
    CMD = "mergecap -F pcap -w "+OUTPUT_PCAP+" "+merge_files
    #print(CMD)
    tp_commands_file.write(CMD+"\n")
    
    print(f"Running: {CMD}")
    run_wireshark(CMD=CMD, outfile=OUTPUT_PCAP, action="Processing FINAL MERGE")
    # process = subprocess.Popen(CMD, shell=True, stdout=subprocess.PIPE)
    # process.wait()
    # merge_returncode = process.returncode
    # if merge_returncode != 0:
    #     msg_final_merge = "ERROR Processing FINAL MERGE file: "+OUTPUT_PCAP+". Return Code="+str(merge_returncode)
    # else:
    #     msg_final_merge = "OK Processing FINAL MERGE file: "+OUTPUT_PCAP+". Return Code="+str(merge_returncode) 

    # print(msg_final_merge)
    # CMD_RETURN_CODES.append(msg_final_merge)
    
    
    tf_commands_file.close()
    tp_commands_file.close()


def main():

    # Cria diretorio ./pcaps se nao existir
    if not os.path.isdir(PCAPS_DIR):
        try:
            os.makedirs(PCAPS_DIR)
        except OSError as exc: # Guard against race condition
            if exc.errno != errno.EEXIST:
                raise

    # Le o arquivo CSV do dataset
    df = pd.read_csv(CSV_FILE, dtype=str)
    print("\n")
    #print(f"Shape {CSV_FILE}: {df.shape}")
    print('{:>20} {}'.format('Shape '+CSV_FILE+':', str(df.shape)))
    #print(df.head())

    # Remove espacos no inicio e no final dos nomes das colunas
    for column in df.columns:
        cws = column
        cws = cws.lstrip()
        cws = cws.rstrip()
        df.rename(columns={column: cws}, inplace=True)

    # Separa amostras classificadas como Normal
    DF_NORMAL = df.loc[(df['label'] == 'NORMAL')
                    & (df['dstport'] == DST_PORT)
                    & (df['dstip'] == DST_IP)]

    # Separa amostras classificadas como Syn-flood
    DF_SYN_FLOOD = df.loc[(df['category_2'] == 'SYN-Flood')
                        & (df['dstport'] == DST_PORT)
                        & (df['dstip'] == DST_IP)]


    #print(f"Shape DF_NORMAL: {DF_NORMAL.shape}")
    print('{:>20} {}'.format('Shape DF_NORMAL:', str(DF_NORMAL.shape)))
    #print(DF_NORMAL.head())
    DF_NORMAL.to_csv(CSV_FILE+"_Normal.csv") # Gera csv das amostras Normal

    #print(f"Shape DF_SYN_FLOOD: {DF_SYN_FLOOD.shape}")
    print('{:>20} {}'.format('Shape DF_SYN_FLOOD:', str(DF_SYN_FLOOD.shape)))
    #print(DF_SYN_FLOOD.head())
    DF_SYN_FLOOD.to_csv(CSV_FILE+"_SYN-Flood.csv") # Gera csv das amostras Syn-flood

    print("\n")

    # Extrai pacotes do tráfego normal
    Extrai_Pacotes(DATASET_NAME=DATASET_NAME, DATAFRAME=DF_NORMAL, LABEL="NORMAL", PCAP_FILE=PCAP_FILE, DST_IP=DST_IP, DST_PORT=DST_PORT)

    # Extrai pacotes do tráfego syn-flood
    Extrai_Pacotes(DATASET_NAME=DATASET_NAME, DATAFRAME=DF_SYN_FLOOD, LABEL="SYN-FLOOD", PCAP_FILE=PCAP_FILE, DST_IP=DST_IP, DST_PORT=DST_PORT)


    freturncodes = open(DATASET_NAME+"_cmd_return_codes.log", "w")
    for i in CMD_RETURN_CODES:
        freturncodes.write(i+"\n")

if __name__ == "__main__":
    logfile = script_name+".log"
    sys.stdout = Logger(logfile=logfile)
    main()
