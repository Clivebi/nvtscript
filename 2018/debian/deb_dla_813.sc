if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.890813" );
	script_version( "2021-06-21T11:00:26+0000" );
	script_cve_id( "CVE-2017-5488", "CVE-2017-5489", "CVE-2017-5490", "CVE-2017-5491", "CVE-2017-5492", "CVE-2017-5493", "CVE-2017-5610", "CVE-2017-5611", "CVE-2017-5612" );
	script_name( "Debian LTS: Security Advisory for wordpress (DLA-813-1)" );
	script_tag( name: "last_modification", value: "2021-06-21 11:00:26 +0000 (Mon, 21 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-01-05 00:00:00 +0100 (Fri, 05 Jan 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-30 02:37:00 +0000 (Sat, 30 Jan 2021)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/02/msg00000.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "wordpress on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
3.6.1+dfsg-1~deb7u13.

We recommend that you upgrade your wordpress packages." );
	script_tag( name: "summary", value: "Several vulnerabilities were discovered in wordpress, a web blogging
tool. The Common Vulnerabilities and Exposures project identifies the
following issues.

CVE-2017-5488

Multiple cross-site scripting (XSS) vulnerabilities in
wp-admin/update-core.php in WordPress before 4.7.1 allow remote
attackers to inject arbitrary web script or HTML via the name or
version header of a plugin.

CVE-2017-5489

Cross-site request forgery (CSRF) vulnerability in WordPress before
4.7.1 allows remote attackers to hijack the authentication of
unspecified victims via vectors involving a Flash file upload.

CVE-2017-5490

Cross-site scripting (XSS) vulnerability in the theme-name fallback
functionality in wp-includes/class-wp-theme.php in WordPress before
4.7.1 allows remote attackers to inject arbitrary web script or HTML
via a crafted directory name of a theme, related to
wp-admin/includes/class-theme-installer-skin.php.

CVE-2017-5491

wp-mail.php in WordPress before 4.7.1 might allow remote attackers to
bypass intended posting restrictions via a spoofed mail server with the
mail.example.com name.

CVE-2017-5492

Cross-site request forgery (CSRF) vulnerability in the widget-editing
accessibility-mode feature in WordPress before 4.7.1 allows remote
attackers to hijack the authentication of unspecified victims for
requests that perform a widgets-access action, related to
wp-admin/includes/class-wp-screen.php and wp-admin/widgets.php.

CVE-2017-5493

wp-includes/ms-functions.php in the Multisite WordPress API in WordPress
before 4.7.1 does not properly choose random numbers for keys, which
makes it easier for remote attackers to bypass intended access
restrictions via a crafted site signup or user signup.

CVE-2017-5610

wp-admin/includes/class-wp-press-this.php in Press This in WordPress
before 4.7.2 does not properly restrict visibility of a
taxonomy-assignment user interface, which allows remote attackers to
bypass intended access restrictions by reading terms.

CVE-2017-5611

SQL injection vulnerability in wp-includes/class-wp-query.php in
WP_Query in WordPress before 4.7.2 allows remote attackers to execute
arbitrary SQL commands by leveraging the presence of an affected
plugin or theme that mishandles a crafted post type name.

CVE-2017-5612

Cross-site scripting (XSS) vulnerability in
wp-admin/includes/class-wp-posts-list-table.php in the posts list
table in WordPress before 4.7.2 allows remote attackers to inject
arbitrary web script or HTML via a crafted excerpt." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "wordpress", ver: "3.6.1+dfsg-1~deb7u13", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "wordpress-l10n", ver: "3.6.1+dfsg-1~deb7u13", rls: "DEB7" ) )){
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

