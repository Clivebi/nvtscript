if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2009-December/016406.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.880810" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:P" );
	script_xref( name: "CESA", value: "2009:1648" );
	script_cve_id( "CVE-2009-3563" );
	script_name( "CentOS Update for ntp CESA-2009:1648 centos5 i386" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ntp'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
	script_tag( name: "affected", value: "ntp on CentOS 5" );
	script_tag( name: "insight", value: "The Network Time Protocol (NTP) is used to synchronize a computer's time
  with a referenced time source.

  Robin Park and Dmitri Vinokurov discovered a flaw in the way ntpd handled
  certain malformed NTP packets. ntpd logged information about all such
  packets and replied with an NTP packet that was treated as malformed when
  received by another ntpd. A remote attacker could use this flaw to create
  an NTP packet reply loop between two ntpd servers via a malformed packet
  with a spoofed source IP address and port, causing ntpd on those servers to
  use excessive amounts of CPU time and fill disk space with log messages.
  (CVE-2009-3563)

  All ntp users are advised to upgrade to this updated package, which
  contains a backported patch to resolve this issue. After installing the
  update, the ntpd daemon will restart automatically." );
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
	if(( res = isrpmvuln( pkg: "ntp", rpm: "ntp~4.2.2p1~9.el5.centos.2.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

