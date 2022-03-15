if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.104010" );
	script_version( "2020-07-07T13:54:18+0000" );
	script_tag( name: "last_modification", value: "2020-07-07 13:54:18 +0000 (Tue, 07 Jul 2020)" );
	script_tag( name: "creation_date", value: "2011-06-01 16:32:46 +0200 (Wed, 01 Jun 2011)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Nmap NSE net: path-mtu" );
	script_category( ACT_INIT );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2011 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE net" );
	script_tag( name: "summary", value: "Performs simple Path MTU Discovery to target hosts.

TCP or UDP packets are sent to the host with the DF (don't fragment) bit set and with varying
amounts of data.  If an ICMP Fragmentation Needed is received, or no reply is received after
retransmissions, the amount of data is lowered and another packet is sent.  This continues until
(assuming no errors occur) a reply from the final host is received, indicating the packet reached
the host without being fragmented.

Not all MTUs are attempted so as to not expend too much time or network resources.  Currently the
relatively short list of MTUs to try contains the plateau values from Table 7-1 in RFC 1191, 'Path
MTU Discovery'. Using these values significantly cuts down the MTU search space.  On top of that,
this list is rarely traversed in whole because:     * the MTU of the outgoing interface is used as a
starting point, and     * we can jump down the list when an intermediate router sending a
'can't fragment' message includes its next hop MTU (as described       in RFC 1191 and required by
RFC 1812)" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

