if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882589" );
	script_version( "$Revision: 14058 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-11-13 05:45:20 +0100 (Sun, 13 Nov 2016)" );
	script_cve_id( "CVE-2016-6313" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for libgcrypt CESA-2016:2674 centos6" );
	script_tag( name: "summary", value: "Check the version of libgcrypt" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The libgcrypt library provides
general-purpose implementations of various cryptographic algorithms.

Security Fix(es):

  * A design flaw was found in the libgcrypt PRNG (Pseudo-Random Number
Generator). An attacker able to obtain the first 580 bytes of the PRNG
output could predict the following 20 bytes. (CVE-2016-6313)

Red Hat would like to thank Felix Dorre and Vladimir Klebanov for reporting
this issue." );
	script_tag( name: "affected", value: "libgcrypt on CentOS 6" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "CESA", value: "2016:2674" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2016-November/022141.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "CentOS6"){
	if(( res = isrpmvuln( pkg: "libgcrypt", rpm: "libgcrypt~1.4.5~12.el6_8", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libgcrypt-devel", rpm: "libgcrypt-devel~1.4.5~12.el6_8", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

