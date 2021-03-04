import pyshark
import binascii
import decimal
import csv

"""
FOR ONLY IPV4
features to be extracted
service
flag
src_bytes
dst_bytes
logged_in
count
serror_rate
srv_serror_rate
same_srv_rate
diff_srv_rate
dist_host_srv_count
dist_host_same_srv_rate
dist_host_diff_srv_rate
dist_host_serror_rate
dist_host_srv_serror_rate

Non-dnp3 communication on a dnp3 port? (Boolean)
Checksum Correct or not? (Boolean)
Dnp3 Datalink Payload length == actual payload length(Boolean)
function not implemented message count?
RTT for each packet req/resp Check from sending a function till the time it is received.
In dreaded Function code? (Boolean)
"""


"""
What constitutes a Connection Record:
1. The start time of the connection.
2. The end time of the connection.
3. Originating host. The host that initiated the connection.
4. Originating port. The port on host that initiated the connection.
5. Responding host. The host that responded to the connection.
6. Service also called protocol. The port on the host that responded to the connection.
7. state that the connection ended in. This can be one of the following:

    SF normal SYN/FIN completion
    REJ connection rejected - initial SYN elicited a RST in reply
    S0 state 0: initial SYN seen but no reply
    S1 state 1: connection established (SYN's exchanged), nothing further seen
    S2 state 2: connection established, initiator has closed their side
    S3 state 3: connection established, responder has closed their side

    S4 state 4: SYN ack seen, but no initial SYN seen ------------------>> not implemented delete any connection that's not a member of a connection

    RSTOSn connection reset by the originator when it was in state n
    RSTRSn connection reset by the responder when it was in state n
    SS SYN seen for already partially-closed connection
    SH a state 0 connection was closed before we ever saw the SYN ack

    SHR a state 4 connection was closed before we ever saw the original SYN ------------------>> not implemented delete any connection that's not a member of a connection
    OOS1 SYN ack did not match initial SYN ------------------>> not implemented delete any connection that's not a member of a connection
    OOS2 initial SYN retransmitted with different sequence number ------------------>> not implemented delete any connection that's not a member of a connection

   Note that connections ending in states S2 and S3 (or terminated by RST's after being in this state; e.g., RSTO3) may have
   byte counts associated with them. These connections were "half-closed". If the side that was half-closed was closed by a
   FIN packet, then the FIN packet provides an accurate byte count for the side that was closed, and a lower-bound byte count
   for the other side (from the sequence number ack'd by the FIN). Thus you may trust one of the byte counts, and the other is
   probably equal to or just a bit below the final byte count, though it could be much below if the connection persisted
   half-open for a long time.
8. All the captured packets in the connection

 """


class Dataset():
    def __init__(self,timestamp_precision='second',time_based_feat_intv_sec=1):
        self.conn_id = []
        self.record = {}
        self.timestamp_precision = timestamp_precision
        self.time_based_feat_intv_sec = time_based_feat_intv_sec #in milliseconds

        self.precision = {'second':1,'millisecond':1000,'microsecond':1000000, 'nanosecond':1000000000}
        self.proto = {'1':'icmp','6':'tcp','17':'udp'}

        #pass

    def isnewconnection(self,pkt):
        """
        function for finding out if a pkt is the start of a new connection
        :param pkt: test packet
        :return: true or false
        """
        if (pkt.tcp.flags_syn == '1') and (pkt.tcp.flags_ack == '0'):

            #To capture the exception where the connection request is resent i.e. retransmitted, we use the loop
            #this will ensure that the connections are unique. you can choose to use the retransmissions later.
            for conn in self.conn_id:
                if self.record[conn][0][1:-1]==[pkt.ip.src,pkt[pkt.transport_layer].srcport,
                                                    pkt.ip.dst, pkt[pkt.transport_layer].dstport]:
                    print ("Retransmitted new connection SYN packet seen --Note this is not added as a new conenction since it's part of an already existing connection")
                    return False

            return True
        else:
            return False

    def get_rtt_avg(self, capture, ip,j):
#        print "j",j
        if len(capture) <= 3:
 #           print "in the less than 3 loop"
            return (float(cap[1].sniff_timestamp) - float(cap[0].sniff_timestamp))
        else:

            i = 1
            stillwaitingack = False
            ack_no_waiting = 0
            ackwaiting_src = ''
            start_time = 0

            rtt_list = []

            for pkt in cap:
                # print pkt
                if i > 3:

                    if (pkt.ip.src_host == ip) and (stillwaitingack == False):
#                        print j, "---->", pkt.tcp.seq, pkt.tcp.ack, pkt.tcp.len
                        ack_no_waiting = (int(pkt.tcp.seq) + int(pkt.tcp.len))
                        ackwaiting_src = pkt.ip.dst_host
                        stillwaitingack = True
                        start_time = float(pkt.sniff_timestamp)
#                        print "waiting for ack ", ack_no_waiting, "start_time ", start_time, "\n"
                        i += 1
                        continue
                        # i+=1
                    if (pkt.ip.src_host == ip) and (stillwaitingack == True):
 #                       print j, "---->", pkt.tcp.seq, pkt.tcp.ack, pkt.tcp.len
                        ack_no_waiting = (int(pkt.tcp.seq) + int(pkt.tcp.len))
 #                       print "in second still waiting"
                        start_time = float(pkt.sniff_timestamp)
 #                       print "waiting for ack ", ack_no_waiting, "start_time ", start_time, "\n"
                        i += 1
                        continue

                        # i += 1

                    if (pkt.ip.src_host == ackwaiting_src) and (stillwaitingack == True):
                        if int(pkt.tcp.ack) == ack_no_waiting:
                            stillwaitingack = False
                            seen_time = float(pkt.sniff_timestamp)
 #                           print j, "<----", pkt.tcp.seq, pkt.tcp.ack
  #                          print "seen waiting for ack ", ack_no_waiting
                            rtt = seen_time - start_time
                            rtt_list.append(rtt)

#                            print "round trip time (sec) ", rtt, "\n"
                            # i += 1

                i += 1

            avg = sum(rtt_list) / len(rtt_list)
            return avg

    def addnewconnection(self,pkt,count):
        """
        function for adding a new connection and its name to a connection list when new one if found
        :param pkt: the test packet
        :param count: the packet number in wireshark
        :return: nothing
        """
        #print pkt.layers ,"\n"
        #print pkt.sniff_timestamp
        #print pkt.ip.src
        #print pkt[pkt.transport_layer].srcport
        #print pkt.ip.dst
        #print pkt[pkt.transport_layer].dstport, '\n'

        # Record Structure:
        # self.record = {'connection_id':[[timestamp,ip.src,srcport, ip.dst,dstport,state],[]]}
        # Note state can be SF,REJ,S0,S1,S2,S3,RSTOSn,RSTRSn,SS or SH. Here, your code should kep updating the state of
        # a connection depending on the packet it sees until the final possible state

        self.record["{0}".format(count)] = [[pkt.sniff_timestamp, pkt.ip.src,
                                                    pkt[pkt.transport_layer].srcport,
                                                    pkt.ip.dst, pkt[pkt.transport_layer].dstport,''], []]
        self.conn_id.append("{0}".format(count))
       # self.conn_no += 1

    def part_of_existing_connection(self,pkt):
        """
        function for adding a pkt to an already existing connection. i.e if a packet is part of an ungoing connection,
        this packet will be appended to that connection
        :param pkt: test packet
        :return:  True/False, connection name
        """
        #print "self.record.keys()",self.record.keys()
        for connection_id in self.record.keys():
            value = self.record[connection_id][0]
            #print "connection_id",connection_id,"value", value
            #print pkt.ip.src, pkt[pkt.transport_layer].srcport, pkt.ip.dst, pkt[pkt.transport_layer].dstport
            option1 = [pkt.ip.src, pkt[pkt.transport_layer].srcport, pkt.ip.dst, pkt[pkt.transport_layer].dstport]
            option2 =[pkt.ip.dst, pkt[pkt.transport_layer].dstport, pkt.ip.src, pkt[pkt.transport_layer].srcport]
            #print option1, option2
            #print option2
            if (option1 == value[1:-1]) or (option2 == value[1:-1]):
                #print "yes part of an existing connection"
                return True, connection_id
            #mind you an attempt to place an else here with return False, None causes some connections to be lost
    def rmv_conn_with_only_1pkt(self):
        print ("deleting connections with only one packet i.e incomplete trace connection due to abrupt wireshark or tcpdump termination")
        print ("for future use of this, do not delete, but attach a state S0 to it.")
        count = 0
        deleted_conns= []
        for connection_id in self.record.keys():
            if len(self.record[connection_id][1])==1:
                #print self.record[connection_id]
                deleted_conns.append(connection_id)
                del self.record[connection_id]
                self.conn_id.remove(connection_id)
                count +=1
        print (count, "connections deleted", "who's connection ID's are: ", deleted_conns)
        print (len(self.conn_id), "connections remaining")

    def insert_conn_state(self):
        # self.record shape is = {'connection_id':[[timestamp,ip.src,srcport, ip.dst,dstport,state],[]]}
        print ("inserting states to the connections")
        for id in self.conn_id:
            #print self.record[id]
            handshake = 0
            closing_fin=0
            for pkt in self.record[id][1]:
                #to insert state S0
                if (self.record[id][0][1] == pkt.ip.src) and (self.record[id][0][5] == '') and (pkt.tcp.flags_syn == '1'):
                    self.record[id][0][5] = 'S0'
                    handshake +=1  #to show that SYN has been seen
                    print ("state S0 added to connection ", id)
                if (self.record[id][0][3] == pkt.ip.src) and (handshake == 1) and \
                        (pkt.tcp.flags_syn == '1') and (pkt.tcp.flags_ack == '1'):
                    handshake +=1
                # To assign to assign state S1
                if (self.record[id][0][1] == pkt.ip.src) and (handshake ==2) and \
                        (pkt.tcp.flags_syn == '0') and (pkt.tcp.flags_ack == '1'):
                    handshake +=1
                    #To indicate that 3 way handshake is successful
                    self.record[id][0][5] = 'S1'
                    print ("state S1 added to connection ", id)

                # to insert state REJ
                if (self.record[id][0][3] == pkt.ip.src) and (self.record[id][0][5] == 'S0') and (pkt.tcp.flags_reset == '1'):
                    self.record[id][0][5] = 'REJ'
                    print ("state REJ added to connection ", id)

                # To assign state to state S3 i.e., responder closed his side of the connection only
                #[0][3] is responder
                #[0][1] is the ip of the initiator
                if (self.record[id][0][3] == pkt.ip.src) and (self.record[id][0][5] == 'S1') and (pkt.tcp.flags_fin == '1'):
                    self.record[id][0][5] = 'S3'
                    closing_fin +=1
                    print ("state S3 added to connection ", id)

                #To insert RSTSn where Sn is the state
                if self.record[id][0][5] == 'S1':
                    #responder
                    if (self.record[id][0][3] == pkt.ip.src) and (pkt.tcp.flags_reset == '1'):
                        self.record[id][0][5] = 'RSTR1'
                    # initiator or originator
                    elif (self.record[id][0][1] == pkt.ip.src) and (pkt.tcp.flags_reset == '1'):
                        self.record[id][0][5] = 'RSTO1'

                # To assign state to state S2 i.e., initiator closed his side of the connection only
                if (self.record[id][0][1] == pkt.ip.src) and (self.record[id][0][5] == 'S1') and (
                    pkt.tcp.flags_fin == '1'):
                    self.record[id][0][5] = 'S2'
                    closing_fin += 1
                    print ("state S2 added to connection ", id)

                # To insert RSTSn where Sn is the state
                if self.record[id][0][5] == 'S2':
                    #responder
                    if (self.record[id][0][3] == pkt.ip.src) and (pkt.tcp.flags_reset == '1'):
                        self.record[id][0][5] = 'RSTR2'
                    #initiator or originator
                    elif (self.record[id][0][1] == pkt.ip.src) and (pkt.tcp.flags_reset == '1'):
                        self.record[id][0][5] = 'RSTO2'

                # To insert RSTSn where Sn is the state
                if self.record[id][0][5] == 'S3':
                    #responder
                    if (self.record[id][0][3] == pkt.ip.src) and (pkt.tcp.flags_reset == '1'):
                        self.record[id][0][5] = 'RSTR3'
                    # initiator or originator
                    elif (self.record[id][0][1] == pkt.ip.src) and (pkt.tcp.flags_reset == '1'):
                        self.record[id][0][5] = 'RSTO3'

                #To set the SNY/FIN state which means that the connection had no errors and hence closed well
                if (closing_fin ==2) or ((self.record[id][0][1] == pkt.ip.src) and (self.record[id][0][5] == 'S3') and (
                    pkt.tcp.flags_fin == '1')) or ((self.record[id][0][3] == pkt.ip.src) and (self.record[id][0][5] == 'S2') and (
                    pkt.tcp.flags_fin == '1')) :
                    self.record[id][0][5] = 'SF'
                    print ("state SF added to connection ", id)

        #print self.record


    def create_record(self,allpackets):
        """
        What constitutes a Connection Record:
        1. The start time of the connection.
        2. The end time of the connection. ---> I will skip this and just put the start time of a connection as mistakes in
            pcap captures might mean that there might not be any fin or rst which are flags used to identify end of a conn.
        3. Originating host. The host that initiated the connection.
        4. Originating port. The port on host that initiated the connection.
        5. Responding host. The host that responded to the connection.
        6. Service. The port on the host that responded to the connection.
        7. All the captured packets in the connection

        :param allpackets: all the data packets captured
        :return:
        """
        #Record Structure:
        #self.record = {'connection_id':[[timestamp,ip.src,srcport, ip.dst,dstport,state],[]]}
        #Note state can be SF,REJ,S0,S1,S2,S3,RSTOSn,RSTRSn,SS or SH. Here, your code should kep updating the state of
        # a connection depending on the packet it sees until the final possible state

        count = 1
        for pkt in allpackets:

            #print "timestamp",pkt.sniff_timestamp
          #  try:
           #     pkt.ip.version
          #  except:
          #      print ("contains IPV6 packets, and this application doesn't support it")
           #     exit()
            print ('count', count)

            if (pkt.transport_layer == "TCP"):
                # print pkt.tcp.flags_syn,type(pkt.tcp.flags_syn),pkt.tcp.flags_ack,type(pkt.tcp.flags_ack)

                if self.isnewconnection(pkt):
                    self.addnewconnection(pkt,count)
                    # add this pkt to record
                    # continue
                    try:
                        answer, conn = self.part_of_existing_connection(pkt)
                #print "part_of_existing_connection", answer,conn
                    except:
                        print ("solve")
           #     exit()
                if conn == None:
                    count += 1
                    continue
                if answer == True:
                    #print count," appended to ", conn, "\n"
                    self.record[conn][1].append(pkt)
            count +=1
        #to remove wrongly terminated connections from the dataset
        self.rmv_conn_with_only_1pkt()
        print (self.record, "\n")
        #print self.conn_id

    def get_duration(self,connection_id):

        try:
            duration = abs(float(self.record[connection_id][1][0].sniff_timestamp) - float(self.record[connection_id][1][-1].sniff_timestamp))
            return duration*self.precision[self.timestamp_precision]
        except IndexError:
            print ("Warning: An incomplete connection found in your data-->could be because of a DoS or connection timeout")
            return 0.0

    def get_protocol(self,connection_id):
        """
        This feature indicates the type of transport protocol used in the connection, e.g. TCP,UDP
        :param connection_id:
        :return:
        """
        #print "in get Protocol"
        #print self.record[connection_id]
        return self.proto[self.record[connection_id][1][0].ip.proto]

    def get_service(self,connection_id):
        return self.record[connection_id][0][-2]

    def get_src_bytes(self,connection_id):
        count = 0
        for pkt in self.record[connection_id][1]:
            if pkt.ip.src == self.record[connection_id][0][1]:
                #print pkt.ip.len
                count = count + float('%s'%(pkt.length))
        #print count
        return count

    def get_dst_bytes(self,connection_id):
        count = 0
        for pkt in self.record[connection_id][1]:
            if pkt.ip.dst == self.record[connection_id][0][1]:
                #print pkt.ip.len
                count = count + float('%s'%(pkt.length))
        #print count
        return count

    def get_flag(self,connection_id):
        return self.record[connection_id][0][5]

    def get_urgent_count(self,connection_id):
        count=0
        for pkt in self.record[connection_id][1]:
            if pkt.tcp.flags_urg == '1':
                count = count + 1
        #print count
        return count
    def get_land(self,connection_id):
        #print self.record[connection_id][0][1], self.record[connection_id][0][3]
        if self.record[connection_id][0][1] == self.record[connection_id][0][3]:
            return 1
        else:
            return 0


    def get_time_based_feat(self):
        #for time based calculation Decimal library precision
        #decimal.getcontext().prec = 6
        self.conn_interval_elem = {}
        i=0
        for conn in self.conn_id:
            end = decimal.Decimal('%s'%(self.record[conn][0][0]))
            start = end - decimal.Decimal(self.time_based_feat_intv_sec)

            prev_conn = []
            for con in reversed(self.conn_id[:i]):
                if decimal.Decimal(self.record[con][0][0]) >= start:
                    #print con
                    prev_conn.append(con)
                    #print "conn time", self.record[con][0][0], 'start', start
                else:
                    continue
            self.conn_interval_elem[conn] = prev_conn

            i+=1

    def get_count(self,connection_id):
        """
        The number of connections to the same host as the current connection in the past two seconds(
        replaced by self.time_based_feat_intv_sec)
        :param connection_id: the id of the connection
        :return: count
        """
        # FOR DNP3 (using only one master and slave), THIS FEATURE IS USELESS SINCE YOU ARE ALWAYS CONNECTING TO
        # SAME HOST ALWAYS"

        self.same_host_count =0
        self.serror_count = 0           #for getting the serror rate
        self.rerror_count = 0           #for getting the rerror rate
        self.same_srv_rate_count = 0
        self.diff_srv_rate_count = 0

        for con in self.conn_interval_elem[connection_id]:
            #print "self.conn_interval_elem[connection_id]", self.record[con]
            if self.record[con][0][3] == self.record[connection_id][0][3]:
                #For getting serror_rate() use the following if statement
                #print "self.record[con][0][3]",self.record[con][0][3]
                #print "self.record[connection_id][0][3]",self.record[connection_id][0][3]

                state = self.record[con][0][5]
                if (state =='S0') or (state =='S1') or (state =='S2') or (state =='S3'):
                    self.serror_count +=1

                #for getting rerror_rate() use the following if statement
                if (state =='REJ'):
                    self.rerror_count +=1

                if self.record[con][0][4] == self.record[connection_id][0][4]:
                    self.same_srv_rate_count +=1

                #for getting diff_srv_rate()

                if self.record[con][0][4] != self.record[connection_id][0][4]:
                    self.diff_srv_rate_count +=1



                self.same_host_count += 1

        return self.same_host_count

    def get_srv_count(self, connection_id):
        """
        The number of connections to the same service as the current connections in the past two seconds(
        replaced by self.time_based_feat_intv_sec).
        :param connection_id:the id of the connection
        :return: srv_count
        """
        self.same_srv_count = 0
        self.srv_serror_count = 0
        self.srv_rerror_count = 0
        self.srv_diff_host_count = 0

        for con in self.conn_interval_elem[connection_id]:
            #same destination port. Note that self.record[0][4] is the destination port
            if self.record[con][0][4] == self.record[connection_id][0][4]:
                #For getting srv_serror_rate() use the following if statement
                state = self.record[con][0][5]
                if (state =='S0') or (state =='S1') or (state =='S2') or (state =='S3'):
                    self.srv_serror_count +=1

                #for getting srv_rerror_rate()
                if state == 'REJ':
                    self.srv_rerror_count +=1

                if self.record[con][0][3] != self.record[connection_id][0][3]:
                    self.srv_diff_host_count +=1


                self.same_srv_count += 1
        return self.same_srv_count

    def get_serror_rate(self):
        """
        The rate of connections to the same host as the current connection in the past two seconds that have 'SYN' errors.
        SYN error means that you have either state S0,S1,S2 or S3
        :param connection_id:
        :return:
        """
        try:
            return float(self.serror_count) / self.same_host_count
        except:
            return 0.0

    def get_srv_serror_rate(self):
        """
        The rate of connections to the same service as the current connections in the past two seconds that have 'SYN' errors.
        :param connection_id:
        :return:
        """
        try:
            return float(self.srv_serror_count) / self.same_srv_count
        except:
            return 0.0

    def get_rerror_rate(self):
        """
        Same as with 'Serror rate' only with 'REJ' errors instead of 'SYN.'
        :return:
        """
        try:
            pass
            return float(self.rerror_count) / self.same_host_count
        except:
            return 0.0

    def get_srv_rerror_rate(self):
        """
        Same as with 'Srv serror rate' only with 'REJ' errors instead of 'SYN.'
        :return:
        """
        try:
            pass
            return float(self.srv_rerror_count) / self.same_srv_count
        except:
            return 0.0

    def get_same_srv_rate(self):
        """
        The percentage of connections that were to the same service, among the connections aggregated in get_count ()
        :return:
        """
        try:
            pass
            return float(self.same_srv_rate_count) / self.same_host_count
        except:
            return 0.0

    def get_diff_srv_rate(self):
        """
        The percentage of connections that were to different services, among the connections aggregated in get_count()
        :return:
        """
        try:
            pass
            return float(self.diff_srv_rate_count) / self.same_host_count
        except:
            return 0.0

    def get_srv_diff_host_rate(self):
        """
        The percentage of connections that were to different destination machines among the connections aggregated in srv_count()
        :return:
        """
        try:
            pass
            return float(self.srv_diff_host_count) / self.same_srv_count
        except:
            return 0.0



    def get_100_connections_ids(self,i):
        #print "in 100 connections folder"
        #print "i", i
        #one_hundred_mem = []
        if (i-100) >= 0:
            b = i-100
        else:
            b = 0
        #print "range(i-1,b-1,-1)", range(i-1,b-1,-1)
        return [j for j in range(i-1,b-1,-1)]

    #self.record = {'connection_id': [[timestamp, ip.src, srcport, ip.dst, dstport, state], []]}

    def get_dst_host_count(self,i):
        """
        Number of connections having the same destination host IP address
        :param i: the location of the connection being investigated
        :return:
        """
        self.dst_host_count = 0
        self.dst_host_srv_count = 0
        self.dst_host_same_srv_rate = 0
        self.dst_host_diff_srv_rate = 0
        self.dst_host_same_src_port_rate = 0
        self.dst_host_srv_diff_host_rate = 0
        self.dst_host_srv_serror_rate = 0
        self.dst_host_srv_rerror_rate = 0
        self.dst_host_serror_rate = 0
        self.dst_host_rerror_rate = 0

        one_hundred_id_index = self.get_100_connections_ids(i)
        for index in one_hundred_id_index:
            #print "self.conn_id[index]",self.conn_id[index]

            connection_id = self.conn_id[index]
            #print "part of 100",connection_id, "main",self.conn_id[i]
            if self.record[connection_id][0][3] == self.record[self.conn_id[i]][0][3]:
                self.dst_host_count +=1

                #for get_dst_host_same_srv_rate()
                if self.record[connection_id][0][4] == self.record[self.conn_id[i]][0][4]:
                    self.dst_host_same_srv_rate +=1

                #for get_dst_host_diff_srv_rate()
                if self.record[connection_id][0][4] != self.record[self.conn_id[i]][0][4]:
                    self.dst_host_diff_srv_rate +=1

                #For getting get_dst_host_serror_rate() use the following if statement
                state = self.record[connection_id][0][5]
                if (state =='S0') or (state =='S1') or (state =='S2') or (state =='S3'):
                    self.dst_host_serror_rate +=1

                #for getting get_dst_host_rerror_rate()
                if state == 'REJ':
                    self.dst_host_rerror_rate +=1


#-------------------------------------->>>>>>>>>>>>>



            #To get the dst_host_srv_count
            # same destination port. Note that self.record[0][4] is the destination port
            if self.record[connection_id][0][4] == self.record[self.conn_id[i]][0][4]:
                self.dst_host_srv_count +=1

                # To get the get_dst_host_same_src_port_rate
                # same source port from the same destination port. Note that self.record[0][2] is the source port
                if self.record[connection_id][0][2] == self.record[self.conn_id[i]][0][2]:
                    self.dst_host_same_src_port_rate +=1

                # To get the get_dst_host_srv_diff_host_rate
                #Note the self.record[self.conn_id[i]][0][3] is the destination machine ip.
                if self.record[connection_id][0][3] != self.record[self.conn_id[i]][0][3]:
                    self.dst_host_srv_diff_host_rate +=1

                #For getting get_dst_host_srv_serror_rate() use the following if statement
                state = self.record[connection_id][0][5]
                if (state =='S0') or (state =='S1') or (state =='S2') or (state =='S3'):
                    self.dst_host_srv_serror_rate +=1

                #for getting get_dst_host_srv_rerror_rate()
                if state == 'REJ':
                    self.dst_host_srv_rerror_rate +=1


        return self.dst_host_count

    def get_dst_host_srv_count(self,i):
        """
        Number of connections having the same port number
        :param i:
        :return:
        """
        try:
            pass
            return self.dst_host_srv_count
        except:
            return 0.0


    def get_dst_host_same_srv_rate(self,i):

        """
        The percentage of connections that were to the same service, among the connections aggregated in dst_host_count()
        :return:
        """
        try:
            pass
            return  float(self.dst_host_same_srv_rate)/self.dst_host_count
        except:
            return 0.0

    def get_dst_host_diff_srv_rate(self,i):
        """
        The percentage of connections that were to different services,among the connections aggregated in dst_host_count()
        :param i:
        :return:
        """
        try:
            pass
            return float(self.dst_host_diff_srv_rate)/self.dst_host_count
        except:
            return 0.0


    def get_dst_host_same_src_port_rate(self,i):
        """
        The percentage of connections that were from the same source port, among the connections aggregated in dst_host_srv_count()
        :param i:
        :return:
        """
        try:
            pass
            return float(self.dst_host_same_src_port_rate)/self.dst_host_srv_count
        except:
            return 0.0

    def get_dst_host_srv_diff_host_rate(self,i):
        """
        The percentage of connections that were to different destination machines,among the connections aggregated in dst_host_srv_count()
        :param i:
        :return:
        """
        try:
            pass
            return float(self.dst_host_srv_diff_host_rate)/self.dst_host_srv_count
        except:
            return 0.0

    def get_dst_host_srv_serror_rate(self,i):
        """
        The percent of connections that have activated the flag () s0, s1, s2 or s3, among the connections aggregated in dst_host_srv_count()
        :param i:
        :return:
        """
        try:
            pass
            return float(self.dst_host_srv_serror_rate)/self.dst_host_srv_count
        except:
            return 0.0

    def get_dst_host_srv_rerror_rate(self,i):
        """
        The percentage of connections that have activated the flag() REJ,among the connections aggregated in dst_host_srv_count()
        :param i:
        :return:
        """
        try:
            pass
            return float(self.dst_host_srv_rerror_rate)/self.dst_host_srv_count
        except:
            return 0.0

    def get_dst_host_serror_rate(self,i):
        """
        The percentage of connections that have activated the flag () s0, s1,s2 or s3, among the connections aggregated in dst_host_count()
        :param i:
        :return:
        """
        try:
            pass
            return float(self.dst_host_serror_rate)/self.dst_host_count
        except:
            return 0.0

    def get_dst_host_rerror_rate(self,i):
        """
        The percentage of connections that have activated the flag() REJ,among the connections aggregated in dst_host_count()
        :param i:
        :return:
        """
        try:
            pass
            return float(self.dst_host_rerror_rate)/self.dst_host_count
        except:
            return 0.0

    def contains_dnp3_pckt(self,connection_id):
        count = False
        for pkt in self.record[connection_id][1]:
            if pkt.highest_layer =='DNP3':
                count = True
                break
        return count

    def tot_dnp3_payload_len(self,connection_id):
        """
        the total payload of all DNP3 payload in the connection
        :param connection_id:
        :return:
        """
        #print "self.record[connection_id]",self.record[connection_id]
        count = 0
        if '20000' in self.record[connection_id][0]:
        #if (self.record[connection_id][0][2] or self.record[connection_id][0][4]) == '20000':
            #print "it is going to dnp3"
            for pkt in self.record[connection_id][1]:
                if pkt.highest_layer == 'DNP3':
                    count += int(pkt.dnp3.len)
            return count
        else:
            return 0

    def min_payload_len(self,connection_id):
        """
        the minimum DNP3 payload length  in the connection. For the DoS packets, this value might be much lower or higher
        than the DNP3 packets.
        :param connection_id:
        :return: the minimum payload length
        """
        i=0
        count = 0
        if '20000' in self.record[connection_id][0]:
        #if (self.record[connection_id][0][2] or self.record[connection_id][0][4]) == '20000':
            for pkt in self.record[connection_id][1]:
                if pkt.highest_layer == 'DNP3':
                    if i == 0:
                        count = int(pkt.dnp3.len)
                        i=1
                    else:
                        if int(pkt.dnp3.len) < count:
                            count = int(pkt.dnp3.len)

            return count
        else:
            return 0

    def disable_cold_or_warm_in_conn(self,connection_id):
        """

        :param connection_id:
        :return:
        """
        seen = False
        if '20000' in self.record[connection_id][0]:
        #if (self.record[connection_id][0][2] or self.record[connection_id][0][4]) == '20000':
            for pkt in self.record[connection_id][1]:
                if pkt.highest_layer == 'DNP3':
                    if pkt.tcp.dstport == '20000':
                        #print pkt.dnp3
                        #print "pkt.dnp3.al_func",pkt.dnp3.al_func

                        if pkt.dnp3.al_func in ['13','14','21']:
                            seen =True
            return seen
        else:
            return seen

    def func_code_not_supported_count(self,connection_id):
        count = 0
        if '20000' in self.record[connection_id][0]:
        #if (self.record[connection_id][0][2] or self.record[connection_id][0][4]) == '20000':
            for pkt in self.record[connection_id][1]:
                if pkt.tcp.srcport == '20000':
                    if pkt.highest_layer == 'DNP3':
                        #print "connection_id",connection_id
                        #print "pkt.dnp3", pkt.dnp3
                        #print "pkt.dnp3.al_iin_fcni",pkt.dnp3.al_iin_fcni
                        try:
                            if pkt.dnp3.al_iin_fcni == '1':
                                count +=1
                        except:
                            pass
            return count
        else:
            return count

    def dnp3_rttd(self,connection_id,i):

        capture = self.record[connection_id][1]
        ip = self.record[connection_id][0][1]

        return self.get_rtt_avg(capture, ip,i)
        #pass




    def get_features(self,getDNP3=False):

        i = 0
        #self.get_time_based_feat()
        print ('i = ',i)

        file = open('extracted_dataset_final.csv', 'a')
        h = csv.writer(file)
        data = [
            ['conn_id','duration', 'proto', 'service', 'src_bytes', 'dst_bytes', 'flag', 'urgent', 'land', 'count', 'srv_count',
             'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
             'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate',
             'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
             'dst_host_srv_serror_rate', 'dst_host_srv_rerror_rate', 'dst_host_serror_rate', 'dst_host_rerror_rate',
             'contains_dnp3_pckt','tot_dnp3_payload_len','min_payload_len','disable_cold_or_warm_in_conn', \
                 'func_code_not_supported_count','rttd','fff']]
        h.writerows(data)

        for connection_id in self.conn_id:
            print (self.record[connection_id])

            """
            Basic Features
            """
            duration = self.get_duration(connection_id)
            protocol = self.get_protocol(connection_id)
            service = self.get_service(connection_id)
            src_bytes = self.get_src_bytes(connection_id)
            dst_bytes = self.get_dst_bytes(connection_id)
            flag = self.get_flag(connection_id)
            urgent = self.get_urgent_count(connection_id)
            land = self.get_land(connection_id)
            # #
            #
            #
            """
             Time based Features
            """
            self.get_time_based_feat()
            count = self.get_count(connection_id)
            srv_count = self.get_srv_count(connection_id)
            serror_rate = self.get_serror_rate()
            srv_serror_rate = self.get_srv_serror_rate()
            rerror_rate = self.get_rerror_rate()
            srv_rerror_rate = self.get_srv_rerror_rate()
            same_srv_rate = self.get_same_srv_rate()
            diff_srv_rate = self.get_diff_srv_rate()
            srv_diff_host_rate = self.get_srv_diff_host_rate()
            dst_host_count =  self.get_dst_host_count(i)
            dst_host_srv_count = self.get_dst_host_srv_count(i)
            dst_host_same_srv_rate = self.get_dst_host_same_srv_rate(i)
            dst_host_diff_srv_rate = self.get_dst_host_diff_srv_rate(i)
            dst_host_same_src_port_rate = self.get_dst_host_same_src_port_rate(i)
            dst_host_srv_diff_host_rate = self.get_dst_host_srv_diff_host_rate(i)
            dst_host_srv_serror_rate = self.get_dst_host_srv_serror_rate(i)
            dst_host_srv_rerror_rate = self.get_dst_host_srv_rerror_rate(i)
            dst_host_serror_rate = self.get_dst_host_serror_rate(i)
            dst_host_rerror_rate = self.get_dst_host_rerror_rate(i)

            #print self.dnp3_rttd(connection_id,i)

            #round trip time
            rttd = self.dnp3_rttd(connection_id, i)

            #Get DNP3 Properties
            if getDNP3 == True:
                contains_dnp3_pckt = self.contains_dnp3_pckt(connection_id)
                tot_dnp3_payload_len = self.tot_dnp3_payload_len(connection_id)
                min_payload_len = self.min_payload_len(connection_id)
                disable_cold_or_warm_in_conn = self.disable_cold_or_warm_in_conn(connection_id)
                func_code_not_supported_count = self.func_code_not_supported_count(connection_id)









            # print 'conn_id ',connection_id,"duration:", duration, ' proto:', protocol, ' service:', service, \
            #     ' src_bytes', src_bytes, ' dst_bytes', dst_bytes, ' flag', flag, ' urgent', urgent, ' land', land,\
            #     ' count', count,' srv_count', srv_count,' serror_rate',serror_rate,' srv_serror_rate',srv_serror_rate, \
            #     ' rerror_rate', rerror_rate, ' srv_rerror_rate', srv_rerror_rate, ' same_srv_rate', same_srv_rate,\
            #     ' diff_srv_rate', diff_srv_rate, ' srv_diff_host_rate',srv_diff_host_rate, ' dst_host_count',dst_host_count,\
            #     ' dst_host_srv_count',dst_host_srv_count,' dst_host_same_srv_rate',dst_host_same_srv_rate,\
            #     ' dst_host_diff_srv_rate',dst_host_diff_srv_rate, ' dst_host_same_src_port_rate',dst_host_same_src_port_rate,\
            #     ' dst_host_srv_diff_host_rate',dst_host_srv_diff_host_rate,' dst_host_srv_serror_rate',dst_host_srv_serror_rate,\
            #     ' dst_host_srv_rerror_rate', dst_host_srv_rerror_rate,' dst_host_serror_rate',dst_host_serror_rate,\
            #     ' dst_host_rerror_rate',dst_host_rerror_rate,'contains_dnp3_pckt ',contains_dnp3_pckt, 'tot_dnp3_payload_len ', \
            #     tot_dnp3_payload_len, 'min_payload_len ',min_payload_len,'disable_cold_or_warm_in_conn ',disable_cold_or_warm_in_conn,\
            #     'func_code_not_supported_count ',func_code_not_supported_count, 'rttd ', rttd

            data = [
                [connection_id,duration, protocol, service, src_bytes, dst_bytes, flag, urgent, land, count, srv_count,serror_rate,\
                 srv_serror_rate,rerror_rate, srv_rerror_rate, same_srv_rate, diff_srv_rate,srv_diff_host_rate,\
                 dst_host_count, dst_host_srv_count, dst_host_same_srv_rate,dst_host_diff_srv_rate, dst_host_same_src_port_rate,\
                 dst_host_srv_diff_host_rate,dst_host_srv_serror_rate, dst_host_srv_rerror_rate,dst_host_serror_rate,\
                 dst_host_rerror_rate,contains_dnp3_pckt,tot_dnp3_payload_len,min_payload_len,disable_cold_or_warm_in_conn, \
                 func_code_not_supported_count,rttd]]

            h.writerows(data)



            print(i)
            i +=1
        file.close()

def create_dataset(allpackets):

    dataset = Dataset(timestamp_precision='second',time_based_feat_intv_sec=1) #
    dataset.create_record(allpackets)
    dataset.insert_conn_state()
    print ("\n")
    dataset.get_features(getDNP3=True)
    print (dataset.record)

if __name__ == "__main__":
    cap = pyshark.FileCapture("three.pcap") #normal_mst.pcap #normal_slv.pcap #dos_sa_master1 #test.pcap #slavefourthcaptureDoS.pcap dnp3dataset_capture
    create_dataset(cap)
    #, display_filter="frame.number <= 1500"
    print ("GO THROUGH ALL THE HOST-BASED FEATURES BY PRINTING THE CODE AND CONFIRMING THAT IT IS DOING WHAT THE IF FUNCTIONS HAVE BEEN SET TO DO")

    print ("\nmind you that in DoS usign any of the tools, the connections are not unique or they are duplicates a very much")
    print ("lots of them. Hence, if you confirm this after performing DDoS attack, then write a seperate script to clean this up.")
    print ("You can add this script to this code or find a way to ensure that-------->> ")
    print ("not EDITCAP can be used for this http://www.wireshark.org/docs/man-pages/editcap.html")
