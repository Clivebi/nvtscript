if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120554" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2015-09-08 13:29:29 +0200 (Tue, 08 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2013-170)" );
	script_tag( name: "insight", value: "It was discovered that CUPS administrative users (members of the SystemGroups groups) who are permitted to perform CUPS configuration changes via the CUPS web interface could manipulate the CUPS configuration to gain unintended privileges. Such users could read or write arbitrary files with the privileges of the CUPS daemon, possibly allowing them to run arbitrary code with root privileges. (CVE-2012-5519 )After installing this update, the ability to change certain CUPS configuration directives remotely will be disabled by default. The newly introduced ConfigurationChangeRestriction directive can be used to enable the changing of the restricted directives remotely." );
	script_tag( name: "solution", value: "Run yum update cups to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2013-170.html" );
	script_cve_id( "CVE-2012-5519" );
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
	if(!isnull( res = isrpmvuln( pkg: "cups-debuginfo", rpm: "cups-debuginfo~1.4.2~50.18.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cups-libs", rpm: "cups-libs~1.4.2~50.18.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cups-devel", rpm: "cups-devel~1.4.2~50.18.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cups-lpd", rpm: "cups-lpd~1.4.2~50.18.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cups-php", rpm: "cups-php~1.4.2~50.18.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cups", rpm: "cups~1.4.2~50.18.amzn1", rls: "AMAZON" ) )){
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

