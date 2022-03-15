if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120704" );
	script_version( "2021-09-17T13:01:55+0000" );
	script_tag( name: "creation_date", value: "2016-10-26 15:38:13 +0300 (Wed, 26 Oct 2016)" );
	script_tag( name: "last_modification", value: "2021-09-17 13:01:55 +0000 (Fri, 17 Sep 2021)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2016-715)" );
	script_tag( name: "insight", value: "A problem was identified in nginx code responsible for saving client request body to a temporary file. A specially crafted request might result in worker process crash due to a NULL pointer dereference while writing client request body to a temporary file." );
	script_tag( name: "solution", value: "Run yum update nginx to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2016-715.html" );
	script_cve_id( "CVE-2016-4450" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-16 20:17:00 +0000 (Mon, 16 Nov 2020)" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/amazon_linux", "ssh/login/release" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "The remote host is missing an update announced via the referenced Security Advisory." );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
	if(!isnull( res = isrpmvuln( pkg: "nginx-debuginfo", rpm: "nginx-debuginfo~1.8.1~3.27.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nginx", rpm: "nginx~1.8.1~3.27.amzn1", rls: "AMAZON" ) )){
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

