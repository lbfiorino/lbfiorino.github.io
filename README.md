# GitHub Luciano B. Fiorino

## Experimento de replicação de *traces* de pacotes contidos em arquivos PCAP de um *dataset* da literatura

### _Dataset_ utilizado:  NDSec-1
[https://www2.hs-fulda.de/NDSec/NDSec-1/](https://www2.hs-fulda.de/NDSec/NDSec-1/)  
[https://www2.hs-fulda.de/NDSec/NDSec-1/Files/](https://www2.hs-fulda.de/NDSec/NDSec-1/Files/)  

O *dataset* NDSec-1 é formado por 04 (quatro) grupos de *traces* contendo vários tipos de tráfegos. Para o experimento foi escolhido o grupo ***Botnet***.

### Tráfegos extraídos do *dataset*
Os arquivos PCAP a seguir contém os tráfegos extraídos para o experimento de forma estratificada, onde um arquivo PCAP foi gerado para cada tipo de tráfego.

 - *[botnet_SYN-FLOOD.pcap](replay-ndsec1/botnet_SYN-FLOOD.pcap)* : Tráfego de ataque SYN-Flood;
 - *[botnet_NORMAL.pcap](replay-ndsec1/botnet_NORMAL.pcap)* : Tráfego Normal HTTP.


### Tráfegos modificados
 - *[botnet_SYN-FLOOD_mac-ip_mod.pcap](replay-ndsec1/botnet_SYN-FLOOD_mac-ip_mod.pcap)* : Tráfego SYN-Flood com MAC e IP alterados;
 - *[botnet_NORMAL_mac-ip_mod.pcap](replay-ndsec1/botnet_NORMAL_mac-ip_mod.pcap)* : Tráfego Normal com MAC e IP alterados;
 - *[botnet_NORMAL_mac-ip_mod_httphost_mod.pcap](replay-ndsec1/botnet_NORMAL_mac-ip_mod_httphost_mod.pcap)* : Tráfego Normal com MAC, IP e HTTP *host/referer* alterados.


### Capturas dos Tráfegos Replicados
 - *[botnet_NORMAL_replay.pcap](replay-ndsec1/botnet_NORMAL_replay.pcap)* : Tráfego Normal replicado com o script desenvolvido;
 - *[botnet_SYN-FLOOD_replay_moongen.pcap](replay-ndsec1/botnet_SYN-FLOOD_replay_moongen.pcap)* : Tráfego SYN-Flood replicado com a ferramenta MoonGen;
 - *[botnet_SYN-FLOOD_replay_tcpreplay.pcap](replay-ndsec1/botnet_SYN-FLOOD_replay_tcpreplay.pcap)* : Tráfego SYN-Flood replicado com a ferramenta Tcpreplay.


### Códigos Python
 - *[agent-gnocchi-offline.py](replay-ndsec1/agent-gnocchi-offline.py)* : Script para coletar as métricas no Gnocchi;
 - *[botnet_extract_normal_syn-flood.py](replay-ndsec1/botnet_extract_normal_syn-flood.py)* : Script para extrair os tráfegos Normal/Syn-Flood do *dataset* NDSec-1 e gerar os arquivos PCAP para replicação;
 - *[edit_http_request_pcap.py](replay-ndsec1/edit_http_request_pcap.py)* : Script para editar os campos *Host* e *Referer* do cabeçalho HTTP;
 - *[edit_packet_timestamp.py](replay-ndsec1/edit_packet_timestamp.py)* : Script para editar a precisão (casas decimais) do *timestamp* para extrair os pacotes corretamente;
 - *[replay_normal.py](replay-ndsec1/replay_normal.py)* : Script para replicar o tráfego normal utilizando Python Requests.


### Dataset de Telemetria Gerado
*Dataset* gerado a partir das coletas das métricas do serviço de telemetria OpenStack. A política de coleta do serviço de telemetria estava configurada com granularidade de 5 segundos. Dessa forma, cada amostra do *dataset* gerado corresponde a coletas das métricas a cada 5 segundos.

 - *[telemetry_dataset_replay.csv](replay-ndsec1/telemetry_dataset_replay.csv)*
 
