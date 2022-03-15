if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892141" );
	script_version( "2021-07-26T02:01:39+0000" );
	script_cve_id( "CVE-2020-10184", "CVE-2020-10185" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-26 02:01:39 +0000 (Mon, 26 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-03-12 23:15:00 +0000 (Thu, 12 Mar 2020)" );
	script_tag( name: "creation_date", value: "2020-03-18 10:44:51 +0000 (Wed, 18 Mar 2020)" );
	script_name( "Debian LTS: Security Advisory for yubikey-val (DLA-2141-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/03/msg00014.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2141-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'yubikey-val'
  package(s) announced via the DLA-2141-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The following CVEs were reported against yubikey-val.

CVE-2020-10184

The verify endpoint in YubiKey Validation Server before 2.40 does
not check the length of SQL queries, which allows remote attackers
to cause a denial of service, aka SQL injection.

CVE-2020-10185

The sync endpoint in YubiKey Validation Server before 2.40 allows
remote attackers to replay an OTP." );
	script_tag( name: "affected", value: "'yubikey-val' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
2.27-1+deb8u1.

We recommend that you upgrade your yubikey-val packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "yubikey-val", ver: "2.27-1+deb8u1", rls: "DEB8" ) )){
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

