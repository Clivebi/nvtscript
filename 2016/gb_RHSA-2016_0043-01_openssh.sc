if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.871540" );
	script_version( "$Revision: 12497 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2016-01-15 06:14:43 +0100 (Fri, 15 Jan 2016)" );
	script_cve_id( "CVE-2016-0777", "CVE-2016-0778" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:S/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "RedHat Update for openssh RHSA-2016:0043-01" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openssh'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "OpenSSH is OpenBSD's SSH (Secure Shell)
protocol implementation. These packages include the core files necessary for
both the OpenSSH client and server.

An information leak flaw was found in the way the OpenSSH client roaming
feature was implemented. A malicious server could potentially use this flaw
to leak portions of memory (possibly including private SSH keys) of a
successfully authenticated OpenSSH client. (CVE-2016-0777)

A buffer overflow flaw was found in the way the OpenSSH client roaming
feature was implemented. A malicious server could potentially use this flaw
to execute arbitrary code on a successfully authenticated OpenSSH client if
that client used certain non-default configuration options. (CVE-2016-0778)

Red Hat would like to thank Qualys for reporting these issues.

All openssh users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. After installing this
update, the OpenSSH server daemon (sshd) will be restarted automatically." );
	script_tag( name: "affected", value: "openssh on Red Hat Enterprise Linux Server (v. 7)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "RHSA", value: "2016:0043-01" );
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2016-January/msg00020.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Red Hat Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/rhel", "ssh/login/rpms",  "ssh/login/release=RHENT_7" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "RHENT_7"){
	if(( res = isrpmvuln( pkg: "openssh", rpm: "openssh~6.6.1p1~23.el7_2", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "openssh-askpass", rpm: "openssh-askpass~6.6.1p1~23.el7_2", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "openssh-clients", rpm: "openssh-clients~6.6.1p1~23.el7_2", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "openssh-debuginfo", rpm: "openssh-debuginfo~6.6.1p1~23.el7_2", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "openssh-keycat", rpm: "openssh-keycat~6.6.1p1~23.el7_2", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "openssh-server", rpm: "openssh-server~6.6.1p1~23.el7_2", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

