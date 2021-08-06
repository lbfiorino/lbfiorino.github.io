# GitHub Luciano B. Fiorino

## Experimento de replicação de *traces* de pacotes contidos em arquivos PCAP de um *dataset* da literatura

Este experimento teve como objetivo investigar o uso de ferramentas abertas para replicação de *traces* de pacotes de um *dataset* da literatura, a fim de coletar novas métricas de para os *traces* originais. A coleta de novos dados para os mesmos *traces* podem gerar um novo *datasets* ou estender o *dataset* original, permitindo comparar a relevância das novas métricas com as originalmente coletadas em algoritmos de aprendizado de máquina.


### _Dataset_ utilizado:  NDSec-1
[https://www2.hs-fulda.de/NDSec/NDSec-1/](https://www2.hs-fulda.de/NDSec/NDSec-1/)  
[https://www2.hs-fulda.de/NDSec/NDSec-1/Files/](https://www2.hs-fulda.de/NDSec/NDSec-1/Files/)  

O *dataset* NDSec-1 é formado por 04 (quatro) grupos de *traces* contendo vários tipos de tráfegos. Para o experimento foi escolhido o grupo ***Botnet***.

### Tráfegos extraídos do *dataset*
Os arquivos PCAP abaixo contém os tráfegos extraídos para o experimento de forma estratificada, onde um arquivo PCAP foi gerado para cada tipo de tráfego.

 - *[botnet_SYN-FLOOD.pcap](replay-ndsec1/botnet_SYN-FLOOD.pcap)* : Tráfego de ataque SYN-Flood;
 - *[botnet_NORMAL.pcap](replay-ndsec1/botnet_NORMAL.pcap)* : Tráfego Normal HTTP.


### Tráfegos modificados
Os arquivos PCAP abaixo contém os tráfegos extraídos e modificados para o experimento também de forma estratificada.

 - *[botnet_SYN-FLOOD_mac-ip_mod.pcap](replay-ndsec1/botnet_SYN-FLOOD_mac-ip_mod.pcap)* : Tráfego SYN-Flood com MAC e IP alterados;
 - *[botnet_NORMAL_mac-ip_mod.pcap](replay-ndsec1/botnet_NORMAL_mac-ip_mod.pcap)* : Tráfego Normal com MAC e IP alterados;
 - *[botnet_NORMAL_mac-ip_mod_httphost_mod.pcap](replay-ndsec1/botnet_NORMAL_mac-ip_mod_httphost_mod.pcap)* : Tráfego Normal com MAC, IP e HTTP *host/referer* alterados.


### Capturas dos Tráfegos Replicados
Os arquivos PCAP abaixo contém as capturas das replicações dos tráfegos modificados com as ferramentas utilizadas no experimento.

 - *[botnet_NORMAL_replay.pcap](replay-ndsec1/botnet_NORMAL_replay.pcap)* : Tráfego Normal replicado com o script desenvolvido;
 - *[botnet_SYN-FLOOD_replay_moongen.pcap](replay-ndsec1/botnet_SYN-FLOOD_replay_moongen.pcap)* : Tráfego SYN-Flood replicado com a ferramenta MoonGen;
 - *[botnet_SYN-FLOOD_replay_tcpreplay.pcap](replay-ndsec1/botnet_SYN-FLOOD_replay_tcpreplay.pcap)* : Tráfego SYN-Flood replicado com a ferramenta Tcpreplay.


### Códigos Python
A seguir são disponibilizadas os códigos utilizados em cada passo do experimento.
 - *[edit_packet_timestamp.py](replay-ndsec1/edit_packet_timestamp.py)* : Script para editar a precisão (casas decimais) do *timestamp* para extrair os pacotes corretamente;
- *[botnet_extract_normal_syn-flood.py](replay-ndsec1/botnet_extract_normal_syn-flood.py)* : Script para extrair os tráfegos originais Normal/Syn-Flood do *dataset* NDSec-1 e gerar os arquivos PCAP para replicação;
 - *[edit_http_request_pcap.py](replay-ndsec1/edit_http_request_pcap.py)* : Script para editar os campos *Host* e *Referer* do cabeçalho HTTP;
 - *[replay_normal.py](replay-ndsec1/replay_normal.py)* : Script para replicar o tráfego normal utilizando Python Requests;
 - *[agent-gnocchi-offline.py](replay-ndsec1/agent-gnocchi-offline.py)* : Script para coletar as métricas no Gnocchi e gerar o *dataset* do experimento.

### Dataset de Telemetria Gerado
*Dataset* gerado a partir das coletas das métricas do serviço de telemetria OpenStack. A política de coleta do serviço de telemetria estava configurada com granularidade de 5 segundos. Dessa forma, cada amostra do *dataset* gerado corresponde a coletas das métricas a cada 5 segundos.

 - *[telemetry_dataset_replay.csv](replay-ndsec1/telemetry_dataset_replay.csv)*
 
