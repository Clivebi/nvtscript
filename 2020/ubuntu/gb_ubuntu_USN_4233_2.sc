if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844308" );
	script_version( "2020-01-28T10:45:23+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-01-28 10:45:23 +0000 (Tue, 28 Jan 2020)" );
	script_tag( name: "creation_date", value: "2020-01-24 04:00:22 +0000 (Fri, 24 Jan 2020)" );
	script_name( "Ubuntu Update for gnutls28 USN-4233-2" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU18\\.04 LTS|UBUNTU16\\.04 LTS)" );
	script_xref( name: "USN", value: "4233-2" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-January/005288.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gnutls28'
  package(s) announced via the USN-4233-2 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "USN-4233-1 disabled SHA1 being used for digital signature operations in
GnuTLS. In certain network environments, certificates using SHA1 may still
be in use. This update adds the %VERIFY_ALLOW_BROKEN and
%VERIFY_ALLOW_SIGN_WITH_SHA1 priority strings that can be used to
temporarily re-enable SHA1 until certificates can be replaced with a
stronger algorithm.

Original advisory details:

As a security improvement, this update marks SHA1 as being untrusted for
digital signature operations." );
	script_tag( name: "affected", value: "'gnutls28' package(s) on Ubuntu 18.04 LTS, Ubuntu 16.04 LTS." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "UBUNTU18.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "libgnutls30", ver: "3.5.18-1ubuntu1.3", rls: "UBUNTU18.04 LTS" ) )){
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
if(release == "UBUNTU16.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "libgnutls30", ver: "3.4.10-4ubuntu1.7", rls: "UBUNTU16.04 LTS" ) )){
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

