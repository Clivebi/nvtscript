if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120019" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2015-09-08 13:15:11 +0200 (Tue, 08 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2014-458)" );
	script_tag( name: "insight", value: "It was found that RPM could encounter an integer overflow, leading to a stack-based overflow, while parsing a crafted CPIO header in the payload section of an RPM file. This could allow an attacker to modify signed RPM files in such a way that they would execute code chosen by the attacker during package installation.  (CVE-2014-8118 )It was found that RPM wrote file contents to the target installation directory under a temporary name, and verified its cryptographic signature only after the temporary file has been written completely. Under certain conditions, the system interprets the unverified temporary file contents and extracts commands from it. This could allow an attacker to modify signed RPM files in such a way that they would execute code chosen by the attacker during package installation.  Red Hat has published an excellent analysis of this issue.  (CVE-2013-6435 )" );
	script_tag( name: "solution", value: "Run yum update rpm to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2014-458.html" );
	script_cve_id( "CVE-2014-8118", "CVE-2013-6435" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
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
	if(!isnull( res = isrpmvuln( pkg: "rpm", rpm: "rpm~4.11.2~2.58.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rpm-sign", rpm: "rpm-sign~4.11.2~2.58.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rpm-build-libs", rpm: "rpm-build-libs~4.11.2~2.58.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rpm-devel", rpm: "rpm-devel~4.11.2~2.58.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rpm-python", rpm: "rpm-python~4.11.2~2.58.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rpm-debuginfo", rpm: "rpm-debuginfo~4.11.2~2.58.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rpm-build", rpm: "rpm-build~4.11.2~2.58.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rpm-cron", rpm: "rpm-cron~4.11.2~2.58.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rpm-apidocs", rpm: "rpm-apidocs~4.11.2~2.58.amzn1", rls: "AMAZON" ) )){
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

