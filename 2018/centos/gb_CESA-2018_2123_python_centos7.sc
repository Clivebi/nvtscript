if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882919" );
	script_version( "2021-05-25T06:00:12+0200" );
	script_tag( name: "last_modification", value: "2021-05-25 06:00:12 +0200 (Tue, 25 May 2021)" );
	script_tag( name: "creation_date", value: "2018-07-14 05:51:18 +0200 (Sat, 14 Jul 2018)" );
	script_cve_id( "CVE-2016-2183" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-06 16:11:00 +0000 (Wed, 06 Jan 2021)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for python CESA-2018:2123 centos7" );
	script_tag( name: "summary", value: "Check the version of python" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Python is an interpreted, interactive,
  object-oriented programming language, which includes modules, classes,
  exceptions, very high level dynamic data types and dynamic typing. Python
  supports interfaces to many system calls and libraries, as well as to various
  windowing systems.

Security Fix(es):

  * A flaw was found in the way the DES/3DES cipher was used as part of the
TLS/SSL protocol. A man-in-the-middle attacker could use this flaw to
recover some plaintext data by capturing large amounts of encrypted traffic
between TLS/SSL server and client if the communication used a DES/3DES
based ciphersuite. (CVE-2016-2183)

Note: This update modifies the Python ssl module to disable 3DES cipher
suites by default.

Red Hat would like to thank OpenVPN for reporting this issue. Upstream
acknowledges Karthikeyan Bhargavan (Inria) and Gaëtan Leurent (Inria) as
the original reporters." );
	script_tag( name: "affected", value: "python on CentOS 7" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "CESA", value: "2018:2123" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2018-July/022964.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
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
	if(( res = isrpmvuln( pkg: "python", rpm: "python~2.7.5~69.el7_5", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "python-debug", rpm: "python-debug~2.7.5~69.el7_5", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "python-devel", rpm: "python-devel~2.7.5~69.el7_5", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "python-libs", rpm: "python-libs~2.7.5~69.el7_5", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "python-test", rpm: "python-test~2.7.5~69.el7_5", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "python-tools", rpm: "python-tools~2.7.5~69.el7_5", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tkinter", rpm: "tkinter~2.7.5~69.el7_5", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

