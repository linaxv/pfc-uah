# PFC-UAH

## Abstract

The WhatsApp mobile application has become more and more successful over the past few years. This level of success justifies the market share that WhatsApp currently has. Consequently, this application has become the object of many research projects, and this is the reason why a set of published articles aim to show faults in the user information handling process.

During the research phase of this project, the possibility of exploiting some of the detected faults has been evaluated. Special focus has been placed on the plain text transmission of a specific packet from users' devices towards WhatsApp servers. The role that this packet plays is fundamental for the operation of the application, as it establishes the relationship between the user's identifier and the IP address within the communications network that it belongs to. In addition, when studying network use (which has been used during the development of the project), the information contained in the packet is extremely useful as it univocally identifies the user within a communications network.

Having evaluated different use cases based on the exploitation of the information contained in this packet, the idea of developing a tool that allows us to study how users use the network came about. This tool is called 'wa-profiler' and receives sample traffic containing WhatsApp data. Its operation is based on associating the volume from each user thanks to the relationship provided by the packet under investigation.

Finally, the tool displays the information graphically (Elasticsearch + Kibana + Grafana), making it easier to understand the true value of the processed information. As a result of a detailed analysis of the represented events, it can be concluded that the developed tool provides multiple possibilities to conduct a detailed study of user behaviour in the use of the WhatsApp application.
