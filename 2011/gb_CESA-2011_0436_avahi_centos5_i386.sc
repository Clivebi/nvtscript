if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2011-April/017293.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.880557" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_xref( name: "CESA", value: "2011:0436" );
	script_cve_id( "CVE-2011-1002", "CVE-2010-2244" );
	script_name( "CentOS Update for avahi CESA-2011:0436 centos5 i386" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'avahi'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
	script_tag( name: "affected", value: "avahi on CentOS 5" );
	script_tag( name: "insight", value: "Avahi is an implementation of the DNS Service Discovery and Multicast DNS
  specifications for Zero Configuration Networking. It facilitates service
  discovery on a local network. Avahi and Avahi-aware applications allow you
  to plug your computer into a network and, with no configuration, view other
  people to chat with, view printers to print to, and find shared files on
  other computers.

  A flaw was found in the way the Avahi daemon (avahi-daemon) processed
  Multicast DNS (mDNS) packets with an empty payload. An attacker on the
  local network could use this flaw to cause avahi-daemon on a target system
  to enter an infinite loop via an empty mDNS UDP packet. (CVE-2011-1002)

  All users are advised to upgrade to these updated packages, which contain
  a backported patch to correct this issue. After installing the update,
  avahi-daemon will be restarted automatically." );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "CentOS5"){
	if(( res = isrpmvuln( pkg: "avahi", rpm: "avahi~0.6.16~10.el5_6", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "avahi-compat-howl", rpm: "avahi-compat-howl~0.6.16~10.el5_6", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "avahi-compat-howl-devel", rpm: "avahi-compat-howl-devel~0.6.16~10.el5_6", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "avahi-compat-libdns_sd", rpm: "avahi-compat-libdns_sd~0.6.16~10.el5_6", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "avahi-compat-libdns_sd-devel", rpm: "avahi-compat-libdns_sd-devel~0.6.16~10.el5_6", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "avahi-devel", rpm: "avahi-devel~0.6.16~10.el5_6", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "avahi-glib", rpm: "avahi-glib~0.6.16~10.el5_6", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "avahi-glib-devel", rpm: "avahi-glib-devel~0.6.16~10.el5_6", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "avahi-qt3", rpm: "avahi-qt3~0.6.16~10.el5_6", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "avahi-qt3-devel", rpm: "avahi-qt3-devel~0.6.16~10.el5_6", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "avahi-tools", rpm: "avahi-tools~0.6.16~10.el5_6", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

