if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892202" );
	script_version( "2021-07-27T02:00:54+0000" );
	script_cve_id( "CVE-2019-14846", "CVE-2020-1733", "CVE-2020-1739", "CVE-2020-1740" );
	script_tag( name: "cvss_base", value: "3.7" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-27 02:00:54 +0000 (Tue, 27 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-06-13 04:15:00 +0000 (Sat, 13 Jun 2020)" );
	script_tag( name: "creation_date", value: "2020-05-06 03:00:09 +0000 (Wed, 06 May 2020)" );
	script_name( "Debian LTS: Security Advisory for ansible (DLA-2202-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/05/msg00005.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2202-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/942188" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ansible'
  package(s) announced via the DLA-2202-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several vulnerabilities were discovered in Ansible, a configuration
management, deployment, and task execution system.

CVE-2019-14846

Ansible was logging at the DEBUG level which lead to a disclosure
of credentials if a plugin used a library that logged credentials
at the DEBUG level. This flaw does not affect Ansible modules, as
those are executed in a separate process.

CVE-2020-1733

A race condition flaw was found when running a playbook with an
unprivileged become user. When Ansible needs to run a module with
become user, the temporary directory is created in /var/tmp. This
directory is created with 'umask 77 && mkdir -p dir', this
operation does not fail if the directory already exists and is
owned by another user. An attacker could take advantage to gain
control of the become user as the target directory can be
retrieved by iterating '/proc/pid/cmdline'.

CVE-2020-1739

A flaw was found when a password is set with the argument
'password' of svn module, it is used on svn command line,
disclosing to other users within the same node. An attacker could
take advantage by reading the cmdline file from that particular
PID on the procfs.

CVE-2020-1740

A flaw was found when using Ansible Vault for editing encrypted
files. When a user executes 'ansible-vault edit', another user on
the same computer can read the old and new secret, as it is
created in a temporary file with mkstemp and the returned file
descriptor is closed and the method write_data is called to write
the existing secret in the file. This method will delete the file
before recreating it insecurely." );
	script_tag( name: "affected", value: "'ansible' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
1.7.2+dfsg-2+deb8u3.

We recommend that you upgrade your ansible packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "ansible", ver: "1.7.2+dfsg-2+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ansible-doc", ver: "1.7.2+dfsg-2+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ansible-fireball", ver: "1.7.2+dfsg-2+deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ansible-node-fireball", ver: "1.7.2+dfsg-2+deb8u3", rls: "DEB8" ) )){
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

