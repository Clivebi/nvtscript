if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120568" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2015-09-08 13:29:45 +0200 (Tue, 08 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2014-276)" );
	script_tag( name: "insight", value: "Varnish before 3.0.5 allows remote attackers to cause a denial of service (child-process crash and temporary caching outage) via a GET request with trailing whitespace characters and no URI.varnish 3.0.3 uses world-readable permissions for the /var/log/varnish/ directory and the log files in the directory, which allows local users to obtain sensitive information by reading the files. NOTE: some of these details are obtained from third party information." );
	script_tag( name: "solution", value: "Run yum update varnish to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2014-276.html" );
	script_cve_id( "CVE-2013-4484", "CVE-2013-0345" );
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
	if(!isnull( res = isrpmvuln( pkg: "varnish-debuginfo", rpm: "varnish-debuginfo~3.0.5~1.14.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "varnish-docs", rpm: "varnish-docs~3.0.5~1.14.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "varnish-libs-devel", rpm: "varnish-libs-devel~3.0.5~1.14.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "varnish-libs", rpm: "varnish-libs~3.0.5~1.14.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "varnish", rpm: "varnish~3.0.5~1.14.amzn1", rls: "AMAZON" ) )){
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

