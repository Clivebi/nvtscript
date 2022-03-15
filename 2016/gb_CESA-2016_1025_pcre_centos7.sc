if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882492" );
	script_version( "$Revision: 14058 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-05-17 13:39:24 +0200 (Tue, 17 May 2016)" );
	script_cve_id( "CVE-2015-2328", "CVE-2015-3217", "CVE-2015-5073", "CVE-2015-8385", "CVE-2015-8386", "CVE-2015-8388", "CVE-2015-8391", "CVE-2016-3191" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for pcre CESA-2016:1025 centos7" );
	script_tag( name: "summary", value: "Check the version of pcre" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "PCRE is a Perl-compatible regular
expression library.

Security Fix(es):

  * Multiple flaws were found in the way PCRE handled malformed regular
expressions. An attacker able to make an application using PCRE process a
specially crafted regular expression could use these flaws to cause the
application to crash or, possibly, execute arbitrary code. (CVE-2015-8385,
CVE-2016-3191, CVE-2015-2328, CVE-2015-3217, CVE-2015-5073, CVE-2015-8388,
CVE-2015-8391, CVE-2015-8386)" );
	script_tag( name: "affected", value: "pcre on CentOS 7" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "CESA", value: "2016:1025" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2016-May/021883.html" );
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
	if(( res = isrpmvuln( pkg: "pcre", rpm: "pcre~8.32~15.el7_2.1", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "pcre-devel", rpm: "pcre-devel~8.32~15.el7_2.1", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "pcre-static", rpm: "pcre-static~8.32~15.el7_2.1", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "pcre-tools", rpm: "pcre-tools~8.32~15.el7_2.1", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

