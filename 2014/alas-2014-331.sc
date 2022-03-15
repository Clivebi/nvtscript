if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120045" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2015-09-08 13:16:11 +0200 (Tue, 08 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2014-331)" );
	script_tag( name: "insight", value: "It was found that the mod_dav module did not correctly strip leading white space from certain elements in a parsed XML. In certain httpd configurations that use the mod_dav module (for example when using the mod_dav_svn module), a remote attacker could send a specially crafted DAV request that would cause the httpd child process to crash or, possibly, allow the attacker to execute arbitrary code with the privileges of the apache user. (CVE-2013-6438 )A buffer over-read flaw was found in the httpd mod_log_config module. In configurations where cookie logging is enabled, a remote attacker could use this flaw to crash the httpd child process via an HTTP request with a malformed cookie header. (CVE-2014-0098 )" );
	script_tag( name: "solution", value: "Run yum update httpd to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2014-331.html" );
	script_cve_id( "CVE-2013-6438", "CVE-2014-0098" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
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
	if(!isnull( res = isrpmvuln( pkg: "httpd-tools", rpm: "httpd-tools~2.2.27~1.2.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "httpd-devel", rpm: "httpd-devel~2.2.27~1.2.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mod_ssl", rpm: "mod_ssl~2.2.27~1.2.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "httpd-debuginfo", rpm: "httpd-debuginfo~2.2.27~1.2.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "httpd-manual", rpm: "httpd-manual~2.2.27~1.2.amzn1", rls: "AMAZON" ) )){
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

