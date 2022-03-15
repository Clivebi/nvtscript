if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882495" );
	script_version( "2021-09-20T13:02:01+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 13:02:01 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-06-03 16:25:18 +0530 (Fri, 03 Jun 2016)" );
	script_cve_id( "CVE-2015-7979", "CVE-2016-1547", "CVE-2016-1548", "CVE-2016-1550", "CVE-2016-2518" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-10 13:15:00 +0000 (Thu, 10 Jun 2021)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for ntp CESA-2016:1141 centos7" );
	script_tag( name: "summary", value: "Check the version of ntp" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The Network Time Protocol (NTP) is used to
synchronize a computer's time with another referenced time source. These packages
include the ntpd service which continuously adjusts system time and utilities
used to query and configure the ntpd service.

Security Fix(es):

  * It was found that when NTP was configured in broadcast mode, a remote
attacker could broadcast packets with bad authentication to all clients.
The clients, upon receiving the malformed packets, would break the
association with the broadcast server, causing them to become out of sync
over a longer period of time. (CVE-2015-7979)

  * A denial of service flaw was found in the way NTP handled preemptible
client associations. A remote attacker could send several crypto NAK
packets to a victim client, each with a spoofed source address of an
existing associated peer, preventing that client from synchronizing its
time. (CVE-2016-1547)

  * It was found that an ntpd client could be forced to change from basic
client/server mode to the interleaved symmetric mode. A remote attacker
could use a spoofed packet that, when processed by an ntpd client, would
cause that client to reject all future legitimate server responses,
effectively disabling time synchronization on that client. (CVE-2016-1548)

  * A flaw was found in the way NTP's libntp performed message
authentication. An attacker able to observe the timing of the comparison
function used in packet authentication could potentially use this flaw to
recover the message digest. (CVE-2016-1550)

  * An out-of-bounds access flaw was found in the way ntpd processed certain
packets. An authenticated attacker could use a crafted packet to create a
peer association with hmode of 7 and larger, which could potentially
(although highly unlikely) cause ntpd to crash. (CVE-2016-2518)

The CVE-2016-1548 issue was discovered by Miroslav Lichvar (Red Hat)." );
	script_tag( name: "affected", value: "ntp on CentOS 7" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "CESA", value: "2016:1141" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2016-May/021899.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS7" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "CentOS7"){
	if(( res = isrpmvuln( pkg: "ntp", rpm: "ntp~4.2.6p5~22.el7.centos.2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "ntpdate", rpm: "ntpdate~4.2.6p5~22.el7.centos.2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "ntp-doc", rpm: "ntp-doc~4.2.6p5~22.el7.centos.2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "ntp-perl", rpm: "ntp-perl~4.2.6p5~22.el7.centos.2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "sntp", rpm: "sntp~4.2.6p5~22.el7.centos.2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

