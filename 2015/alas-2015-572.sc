if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120278" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2015-09-08 13:22:26 +0200 (Tue, 08 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2015-572)" );
	script_tag( name: "insight", value: "It was found that libuser, as used in the chfn userhelper functionality, does not properly filter out newline characters, which allows an authenticated local attacker to corrupt the /etc/passwd file and cause denial-of-service against the system. (CVE-2015-3245 )A flaw was found in the way the libuser library handled the /etc/passwd file. A local attacker could use an application compiled against libuser (for example, userhelper) to manipulate the /etc/passwd file, which could result in a denial of service or possibly allow the attacker to escalate their privileges to root. (CVE-2015-3246 )" );
	script_tag( name: "solution", value: "Run yum update usermode libuser to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2015-572.html" );
	script_cve_id( "CVE-2015-3245", "CVE-2015-3246" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/amazon_linux", "ssh/login/release" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "The remote host is missing an update announced via the referenced Security Advisory." );
	script_copyright( "Copyright (C) 2015 Eero Volotinen" );
	script_family( "Amazon Linux Local Security Checks" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "AMAZON"){
	if(!isnull( res = isrpmvuln( pkg: "usermode", rpm: "usermode~1.102~3.18.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "usermode-debuginfo", rpm: "usermode-debuginfo~1.102~3.18.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libuser-python", rpm: "libuser-python~0.56.13~8.15.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libuser", rpm: "libuser~0.56.13~8.15.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libuser-debuginfo", rpm: "libuser-debuginfo~0.56.13~8.15.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libuser-devel", rpm: "libuser-devel~0.56.13~8.15.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
exit( 0 );

