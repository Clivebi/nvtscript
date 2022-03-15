if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892535" );
	script_version( "2021-08-25T06:00:59+0000" );
	script_cve_id( "CVE-2017-7481", "CVE-2019-10156", "CVE-2019-14846", "CVE-2019-14904" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-25 06:00:59 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-28 16:38:00 +0000 (Thu, 28 Jan 2021)" );
	script_tag( name: "creation_date", value: "2021-01-29 04:00:07 +0000 (Fri, 29 Jan 2021)" );
	script_name( "Debian LTS: Security Advisory for ansible (DLA-2535-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/01/msg00023.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2535-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2535-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/862666" );
	script_xref( name: "URL", value: "https://bugs.debian.org/930065" );
	script_xref( name: "URL", value: "https://bugs.debian.org/942188" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ansible'
  package(s) announced via the DLA-2535-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "CVE-2017-7481

Ansible fails to properly mark lookup-plugin results as unsafe. If an
attacker could control the results of lookup() calls, they could inject
Unicode strings to be parsed by the jinja2 templating system, resulting in
code execution. By default, the jinja2 templating language is now marked as
'unsafe' and is not evaluated.

CVE-2019-10156

A flaw was discovered in the way Ansible templating was implemented,
causing the possibility of information disclosure through unexpected
variable substitution. By taking advantage of unintended variable
substitution the content of any variable may be disclosed.

CVE-2019-14846

Ansible was logging at the DEBUG level which lead to a disclosure of
credentials if a plugin used a library that logged credentials at the DEBUG
level. This flaw does not affect Ansible modules, as those are executed in
a separate process.

CVE-2019-14904

A flaw was found in the solaris_zone module from the Ansible Community
modules. When setting the name for the zone on the Solaris host, the zone
name is checked by listing the process with the 'ps' bare command on the
remote machine. An attacker could take advantage of this flaw by crafting
the name of the zone and executing arbitrary commands in the remote host." );
	script_tag( name: "affected", value: "'ansible' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, these problems have been fixed in version
2.2.1.0-2+deb9u2.

We recommend that you upgrade your ansible packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "ansible", ver: "2.2.1.0-2+deb9u2", rls: "DEB9" ) )){
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

