if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120615" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2015-12-15 02:51:26 +0200 (Tue, 15 Dec 2015)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2015-625)" );
	script_tag( name: "insight", value: "A flaw was found in the way OpenSSH handled PAM authentication when using privilege separation. An attacker with valid credentials on the system and able to fully compromise a non-privileged pre-authentication process using a different flaw could use this flaw to authenticate as other users.It was discovered that the OpenSSH sshd daemon did not check the list of keyboard-interactive authentication methods for duplicates. A remote attacker could use this flaw to bypass the MaxAuthTries limit, making it easier to perform password guessing attacks.A use-after-free flaw was found in OpenSSH. An attacker able to fully compromise a non-privileged pre-authentication process using a different flaw could possibly cause sshd to crash or execute arbitrary code with root privileges." );
	script_tag( name: "solution", value: "Run yum update openssh to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2015-625.html" );
	script_cve_id( "CVE-2015-6563", "CVE-2015-5600", "CVE-2015-6564" );
	script_tag( name: "cvss_base", value: "8.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:C" );
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
	if(!isnull( res = isrpmvuln( pkg: "openssh", rpm: "openssh~6.6.1p1~22.58.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssh-server", rpm: "openssh-server~6.6.1p1~22.58.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "auth", rpm: "auth~0.9.3~9.22.58.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssh-keycat", rpm: "openssh-keycat~6.6.1p1~22.58.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssh-ldap", rpm: "openssh-ldap~6.6.1p1~22.58.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssh-debuginfo", rpm: "openssh-debuginfo~6.6.1p1~22.58.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssh-clients", rpm: "openssh-clients~6.6.1p1~22.58.amzn1", rls: "AMAZON" ) )){
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

