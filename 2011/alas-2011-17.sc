if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120294" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2015-09-08 11:22:15 +0200 (Tue, 08 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2011-17)" );
	script_tag( name: "insight", value: "The Net::HTTPS module in libwww-perl (LWP) before 6.00, as used in WWW::Mechanize, LWP::UserAgent, and other products, when running in environments that do not set the If-SSL-Cert-Subject header, does not enable full validation of SSL certificates by default, which allows remote attackers to spoof servers via man-in-the-middle (MITM) attacks involving hostnames that are not properly validated. NOTE: it could be argued that this is a design limitation of the Net::HTTPS API, and separate implementations should be independently assigned CVE identifiers for not working around this limitation. However, because this API was modified within LWP, a single CVE identifier has been assigned." );
	script_tag( name: "solution", value: "Run yum update perl-libwww-perl to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2011-17.html" );
	script_cve_id( "CVE-2011-0633" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
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
	if(!isnull( res = isrpmvuln( pkg: "perl-libwww-perl", rpm: "perl-libwww-perl~5.837~4.1.amzn1", rls: "AMAZON" ) )){
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

