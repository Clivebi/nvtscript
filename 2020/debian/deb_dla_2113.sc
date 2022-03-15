if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892113" );
	script_version( "2021-07-23T02:01:00+0000" );
	script_cve_id( "CVE-2020-8631", "CVE-2020-8632" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-07-23 02:01:00 +0000 (Fri, 23 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-02-21 11:15:00 +0000 (Fri, 21 Feb 2020)" );
	script_tag( name: "creation_date", value: "2020-02-22 04:00:05 +0000 (Sat, 22 Feb 2020)" );
	script_name( "Debian LTS: Security Advisory for cloud-init (DLA-2113-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/02/msg00021.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2113-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/951362" );
	script_xref( name: "URL", value: "https://bugs.debian.org/951363" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'cloud-init'
  package(s) announced via the DLA-2113-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "CVE-2020-8631

In cloud-init, relies on Mersenne Twister for a random password,
which makes it easier for attackers to predict passwords, because
rand_str in cloudinit/util.py calls the random.choice function.

CVE-2020-8632

In cloud-init, rand_user_password in
cloudinit/config/cc_set_passwords.py has a small default pwlen
value, which makes it easier for attackers to guess passwords." );
	script_tag( name: "affected", value: "'cloud-init' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
0.7.6~bzr976-2+deb8u1.

We recommend that you upgrade your cloud-init packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "cloud-init", ver: "0.7.6~bzr976-2+deb8u1", rls: "DEB8" ) )){
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

