if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120628" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2016-01-20 07:22:46 +0200 (Wed, 20 Jan 2016)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2016-638)" );
	script_tag( name: "insight", value: "An information leak flaw was found in the way the OpenSSH client roaming feature was implemented. A malicious server could potentially use this flaw to leak portions of memory (possibly including private SSH keys) of a successfully authenticated OpenSSH client.A buffer overflow flaw was found in the way the OpenSSH client roaming feature was implemented. A malicious server could potentially use this flaw to execute arbitrary code on a successfully authenticated OpenSSH client if that client used certain non-default configuration options." );
	script_tag( name: "solution", value: "Run yum update openssh to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2016-638.html" );
	script_cve_id( "CVE-2016-0777", "CVE-2016-0778" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:S/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/amazon_linux", "ssh/login/release" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "The remote host is missing an update announced via the referenced Security Advisory." );
	script_copyright( "Copyright (C) 2016 Eero Volotinen" );
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
	if(!isnull( res = isrpmvuln( pkg: "openssh-server", rpm: "openssh-server~6.6.1p1~23.59.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssh", rpm: "openssh~6.6.1p1~23.59.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssh-ldap", rpm: "openssh-ldap~6.6.1p1~23.59.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "auth", rpm: "auth~0.9.3~9.23.59.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssh-debuginfo", rpm: "openssh-debuginfo~6.6.1p1~23.59.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssh-clients", rpm: "openssh-clients~6.6.1p1~23.59.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssh-keycat", rpm: "openssh-keycat~6.6.1p1~23.59.amzn1", rls: "AMAZON" ) )){
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

