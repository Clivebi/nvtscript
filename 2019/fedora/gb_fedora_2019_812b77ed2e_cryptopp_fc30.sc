if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876431" );
	script_version( "2021-09-01T08:01:24+0000" );
	script_cve_id( "CVE-2017-9434", "CVE-2016-9939" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-01 08:01:24 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-01 06:29:00 +0000 (Sat, 01 Jun 2019)" );
	script_tag( name: "creation_date", value: "2019-06-02 02:13:48 +0000 (Sun, 02 Jun 2019)" );
	script_name( "Fedora Update for cryptopp FEDORA-2019-812b77ed2e" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC30" );
	script_xref( name: "FEDORA", value: "2019-812b77ed2e" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/7IL5A6465IEPW5GAWGXB2ENJPFYVWTJM" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'cryptopp'
  package(s) announced via the FEDORA-2019-812b77ed2e advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Crypto++ Library is a free C++ class library of cryptographic schemes.

One purpose of Crypto++ is to act as a repository of public domain
(not copyrighted) source code. Although the library is copyrighted as a
compilation, the individual files in it are in the public domain." );
	script_tag( name: "affected", value: "'cryptopp' package(s) on Fedora 30." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
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
if(release == "FC30"){
	if(!isnull( res = isrpmvuln( pkg: "cryptopp", rpm: "cryptopp~8.2.0~1.fc30", rls: "FC30" ) )){
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

