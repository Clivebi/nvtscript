if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892484" );
	script_version( "2020-12-09T04:00:07+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-12-09 04:00:07 +0000 (Wed, 09 Dec 2020)" );
	script_tag( name: "creation_date", value: "2020-12-09 04:00:07 +0000 (Wed, 09 Dec 2020)" );
	script_name( "Debian LTS: Security Advisory for python-certbot (DLA-2484-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/12/msg00010.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2484-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/969126" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python-certbot'
  package(s) announced via the DLA-2484-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Let's Encrypt's ACMEv1 API is deprecated and in the process of being
shut down. Beginning with brownouts in January 2021, and ending with
a total shutdown in June 2021, the Let's Encrypt APIs will become
unavailable. To prevent users having disruptions to their certificate
renewals, this update backports the switch over to the ACMEv2 API." );
	script_tag( name: "affected", value: "'python-certbot' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, this problem has been fixed in version
0.28.0-1~deb9u3.

We recommend that you upgrade your python-certbot packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "certbot", ver: "0.28.0-1~deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "letsencrypt", ver: "0.28.0-1~deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-certbot-doc", ver: "0.28.0-1~deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3-certbot", ver: "0.28.0-1~deb9u3", rls: "DEB9" ) )){
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

