if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882375" );
	script_version( "$Revision: 14058 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-01-26 06:10:58 +0100 (Tue, 26 Jan 2016)" );
	script_cve_id( "CVE-2015-8138" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for ntp CESA-2016:0063 centos7" );
	script_tag( name: "summary", value: "Check the version of ntp" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The Network Time Protocol (NTP) is used to
synchronize a computer's time with a referenced time source.

It was discovered that ntpd as a client did not correctly check the
originate timestamp in received packets. A remote attacker could use this
flaw to send a crafted packet to an ntpd client that would effectively
disable synchronization with the server, or push arbitrary offset/delay
measurements to modify the time on the client. (CVE-2015-8138)

All ntp users are advised to upgrade to these updated packages, which
contain a backported patch to resolve this issue. After installing the
update, the ntpd daemon will restart automatically." );
	script_tag( name: "affected", value: "ntp on CentOS 7" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "CESA", value: "2016:0063" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2016-January/021624.html" );
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
	if(( res = isrpmvuln( pkg: "ntp", rpm: "ntp~4.2.6p5~22.el7.centos.1", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "ntpdate", rpm: "ntpdate~4.2.6p5~22.el7.centos.1", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "ntp-doc", rpm: "ntp-doc~4.2.6p5~22.el7.centos.1", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "ntp-perl", rpm: "ntp-perl~4.2.6p5~22.el7.centos.1", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "sntp", rpm: "sntp~4.2.6p5~22.el7.centos.1", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

