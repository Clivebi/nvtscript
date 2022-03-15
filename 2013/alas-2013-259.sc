if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120542" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2015-09-08 13:29:05 +0200 (Tue, 08 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2013-259)" );
	script_tag( name: "insight", value: "A flaw was found in the way sudo handled time stamp files. An attacker able to run code as a local user and with the ability to control the system clock could possibly gain additional privileges by running commands that the victim user was allowed to run via sudo, without knowing the victim's password. (CVE-2013-1775 )It was found that sudo did not properly validate the controlling terminal device when the tty_tickets option was enabled in the /etc/sudoers file. An attacker able to run code as a local user could possibly gain additional privileges by running commands that the victim user was allowed to run via sudo, without knowing the victim's password. (CVE-2013-2776, CVE-2013-2777 )" );
	script_tag( name: "solution", value: "Run yum update sudo to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2013-259.html" );
	script_cve_id( "CVE-2013-1775", "CVE-2013-2777", "CVE-2013-2776" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
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
	if(!isnull( res = isrpmvuln( pkg: "sudo-devel", rpm: "sudo-devel~1.8.6p3~12.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sudo-debuginfo", rpm: "sudo-debuginfo~1.8.6p3~12.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sudo", rpm: "sudo~1.8.6p3~12.17.amzn1", rls: "AMAZON" ) )){
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

