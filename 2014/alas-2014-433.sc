if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120342" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2015-09-08 13:24:06 +0200 (Tue, 08 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2014-433)" );
	script_tag( name: "insight", value: "A flaw was found in the way Squid handled malformed HTTP Range headers. A remote attacker able to send HTTP requests to the Squid proxy could use this flaw to crash Squid. (CVE-2014-3609 )A buffer overflow flaw was found in Squid's DNS lookup module. A remote attacker able to send HTTP requests to the Squid proxy could use this flaw to crash Squid. (CVE-2013-4115 )Squid 3.1 before 3.3.12 and 3.4 before 3.4.4, when SSL-Bump is enabled, allows remote attackers to cause a denial of service (assertion failure) via a crafted range request, related to state management. (CVE-2014-0128 )" );
	script_tag( name: "solution", value: "Run yum update squid to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2014-433.html" );
	script_cve_id( "CVE-2013-4115", "CVE-2014-3609", "CVE-2014-0128" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
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
	if(!isnull( res = isrpmvuln( pkg: "squid", rpm: "squid~3.1.10~29.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "squid-debuginfo", rpm: "squid-debuginfo~3.1.10~29.17.amzn1", rls: "AMAZON" ) )){
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

