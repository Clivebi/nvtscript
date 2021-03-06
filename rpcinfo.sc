if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11111" );
	script_version( "2021-04-14T09:28:27+0000" );
	script_tag( name: "last_modification", value: "2021-04-14 09:28:27 +0000 (Wed, 14 Apr 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Obtain list of all port mapper registered programs via RPC" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 Michel Arboi" );
	script_family( "Service detection" );
	script_dependencies( "secpod_rpc_portmap_tcp.sc" );
	script_mandatory_keys( "rpc/portmap/tcp/detected" );
	script_tag( name: "summary", value: "This script calls the DUMP RPC on the port mapper, to obtain the
  list of all registered programs." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("port_service_func.inc.sc");
portmap = get_kb_item( "rpc/portmap" );
if(!portmap){
	exit( 0 );
}
if(!get_port_state( portmap )){
	exit( 0 );
}
soc = open_sock_tcp( portmap );
if(!soc){
	exit( 0 );
}
report_tcp = make_list();
report_udp = make_list();
rpc_names = "
portmapper      100000  portmap sunrpc rpcbind
rstatd          100001  rstat rup perfmeter rstat_svc
rusersd         100002  rusers
nfs             100003  nfsprog
ypserv          100004  ypprog
mountd          100005  mount showmount
ypbind          100007
walld           100008  rwall shutdown
yppasswdd       100009  yppasswd
etherstatd      100010  etherstat
rquotad         100011  rquotaprog quota rquota
sprayd          100012  spray
3270_mapper     100013
rje_mapper      100014
selection_svc   100015  selnsvc
database_svc    100016
rexd            100017  rex
alis            100018
sched           100019
llockmgr        100020
nlockmgr        100021
x25.inr         100022
statmon         100023
status          100024
bootparam       100026
ypupdated       100028  ypupdate
keyserv         100029  keyserver
sunlink_mapper  100033
tfsd            100037
nsed            100038
nsemntd         100039
showfhd         100043  showfh
ioadmd          100055  rpc.ioadmd
NETlicense      100062
sunisamd        100065
debug_svc       100066  dbsrv
ypxfrd          100069  rpc.ypxfrd
bugtraqd        100071
kerbd           100078
event           100101  na.event        # SunNet Manager
logger          100102  na.logger       # SunNet Manager
sync            100104  na.sync
hostperf        100107  na.hostperf
activity        100109  na.activity     # SunNet Manager
hostmem         100112  na.hostmem
sample          100113  na.sample
x25             100114  na.x25
ping            100115  na.ping
rpcnfs          100116  na.rpcnfs
hostif          100117  na.hostif
etherif         100118  na.etherif
iproutes        100120  na.iproutes
layers          100121  na.layers
snmp            100122  na.snmp snmp-cmc snmp-synoptics snmp-unisys snmp-utk
traffic         100123  na.traffic
nfs_acl         100227
sadmind         100232
nisd            100300  rpc.nisd
nispasswd       100303  rpc.nispasswdd
ufsd            100233  ufsd
pcnfsd          150001  pcnfs
amd             300019  amq
# Legato NetWorker
nsrd            390103  nsr      # NetWorker service
nsrmmd          390104  nsrmm    # NetWorker media mupltiplexor daemon
nsrindexd       390105  nsrindex # NetWorker file index daemon
nsrmmdbd        390107  nsrmmdb  # NetWorker media management database daemon
nsrjb           390110  nsrjbd   # NetWorker jukebox-control service
nsrexec         390113  nsrexecd # NetWorker client execution service
nsrnotd         390400           # NetWorker notary service
#
sgi_fam         391002  fam
netinfobind     200100001
bwnfsd          545580417
fypxfrd         600100069 freebsd-ypxfrd
";
i = 0;
xid1 = rand() % 256;
xid2 = rand() % 256;
xid3 = rand() % 256;
xid4 = rand() % 256;
pack = raw_string( 0x80, 0, 0, 0x28, xid1, xid2, xid3, xid4, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1, 0x86, 0xA0, 0, 0, 0, 2, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 );
send( socket: soc, data: pack );
r = recv( socket: soc, length: 4, min: 4 );
if(strlen( r ) < 4){
	exit( 0 );
}
last_frag = r[0];
y = ord( r[2] ) * 256;
frag_len = y + ord( r[3] );
r = recv( socket: soc, length: 4, min: 4 );
r = recv( socket: soc, length: 4, min: 4 );
y = ord( r[0] ) * 256;
y = y + ord( r[1] );
y = y * 256;
y = y + ord( r[2] );
y = y * 256;
y = y + ord( r[3] );
r = recv( socket: soc, length: 4, min: 4 );
a = ord( r[0] ) * 256;
a = a + ord( r[1] );
a = a * 256;
a = a + ord( r[2] );
a = a * 256;
a = a + ord( r[3] );
r = recv( socket: soc, length: 8, min: 8 );
r = recv( socket: soc, length: 4, min: 4 );
z = ord( r[0] ) * 256;
z = z + ord( r[1] );
z = z * 256;
z = z + ord( r[2] );
z = z * 256;
z = z + ord( r[3] );
if(( y != 1 ) || ( a != 0 ) || ( z != 0 )){
	close( soc );
	exit( 0 );
}
r = recv( socket: soc, length: 4, min: 4 );
vf = ord( r[0] ) * 256;
vf = vf + ord( r[1] );
vf = vf * 256;
vf = vf + ord( r[2] );
vf = vf * 256;
vf = vf + ord( r[3] );
len = 28;
for(;vf;){
	if(len >= frag_len){
		r = recv( socket: soc, length: 4, min: 4 );
		last_frag = ord( r[0] );
		y = ord( r[2] ) * 256;
		frag_len = y + ord( r[3] );
		len = 0;
	}
	r = recv( socket: soc, length: 4, min: 4 );
	len = len + 4;
	z = ord( r[0] ) * 256;
	z = z + ord( r[1] );
	z = z * 256;
	z = z + ord( r[2] );
	z = z * 256;
	z = z + ord( r[3] );
	program = z;
	if(len >= frag_len){
		r = recv( socket: soc, length: 4, min: 4 );
		last_frag = ord( r[0] );
		y = ord( r[2] ) * 256;
		frag_len = y + ord( r[3] );
		len = 0;
	}
	r = recv( socket: soc, length: 4, min: 4 );
	len = len + 4;
	z = ord( r[0] ) * 256;
	z = z + ord( r[1] );
	z = z * 256;
	z = z + ord( r[2] );
	z = z * 256;
	z = z + ord( r[3] );
	version = z;
	if(len >= frag_len){
		r = recv( socket: soc, length: 4, min: 4 );
		last_frag = ord( r[0] );
		y = ord( r[2] ) * 256;
		frag_len = y + ord( r[3] );
		len = 0;
	}
	r = recv( socket: soc, length: 4, min: 4 );
	len = len + 4;
	z = ord( r[0] ) * 256;
	z = z + ord( r[1] );
	z = z * 256;
	z = z + ord( r[2] );
	z = z * 256;
	z = z + ord( r[3] );
	proto = z;
	if(len >= frag_len){
		r = recv( socket: soc, length: 4, min: 4 );
		last_frag = ord( r[0] );
		y = ord( r[2] ) * 256;
		frag_len = y + ord( r[3] );
		len = 0;
	}
	r = recv( socket: soc, length: 4, min: 4 );
	len = len + 4;
	z = ord( r[0] ) * 256;
	z = z + ord( r[1] );
	z = z * 256;
	z = z + ord( r[2] );
	z = z * 256;
	z = z + ord( r[3] );
	port = z;
	if(len >= frag_len){
		r = recv( socket: soc, length: 4, min: 4 );
		last_frag = ord( r[0] );
		y = ord( r[2] ) * 256;
		frag_len = y + ord( r[3] );
		len = 0;
	}
	r = recv( socket: soc, length: 4, min: 4 );
	len = len + 4;
	z = ord( r[0] ) * 256;
	z = z + ord( r[1] );
	z = z * 256;
	z = z + ord( r[2] );
	z = z * 256;
	z = z + ord( r[3] );
	vf = z;
	{
		req = NASLString( "^[a-zA-Z0-9_-]+[ ]+", program );
		str = egrep( string: rpc_names, pattern: req );
		name = ereg_replace( string: str, pattern: NASLString( "^([a-zA-Z0-9_-]+)[ ]+.*" ), replace: "\\1" );
		alias = ereg_replace( string: str, pattern: NASLString( "^[a-zA-Z0-9_-]+[ ]+[0-9]+[ ]*(.*)[\\r\\n]+" ), replace: "\\1" );
		m = NASLString( "RPC program #", program, " version ", version );
		if(name){
			m = NASLString( m, " '", name, "'" );
		}
		if(alias){
			m = NASLString( m, " (", alias, ")" );
		}
		m = NASLString( m, " on port ", port );
		if(proto == 6){
			report_tcp[port] += m + "/TCP\n\n";
			if(port <= 65535 && port > 0){
				if( name ) {
					service_register( port: port, proto: NASLString( "RPC/", name ) );
				}
				else {
					service_register( port: port, proto: NASLString( "RPC/", program ) );
				}
			}
		}
		if(proto == 17){
			report_udp[port] += m + "/UDP\n\n";
		}
		i = i + 1;
	}
}
result = "These are the registered RPC programs:\\n\\n";
for port in keys( report_tcp ) {
	if(port > 0 && port <= 65535){
		result += report_tcp[port];
	}
}
for port in keys( report_udp ) {
	if(port > 0 && port <= 65535){
		result += report_udp[port];
	}
}
log_message( port: portmap, data: result );

