if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876689" );
	script_version( "2021-09-02T08:01:23+0000" );
	script_cve_id( "CVE-2018-14955", "CVE-2018-14954", "CVE-2018-14953", "CVE-2018-14952", "CVE-2018-14951", "CVE-2018-14950", "CVE-2018-8741" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-02 08:01:23 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-15 20:15:00 +0000 (Thu, 15 Aug 2019)" );
	script_tag( name: "creation_date", value: "2019-08-16 02:24:28 +0000 (Fri, 16 Aug 2019)" );
	script_name( "Fedora Update for squirrelmail FEDORA-2019-ad02f64a79" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC30" );
	script_xref( name: "FEDORA", value: "2019-ad02f64a79" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/CVXTYMZ35IC5KPNMAE6BWAQWURMX7KZO" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'squirrelmail'
  package(s) announced via the FEDORA-2019-ad02f64a79 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "SquirrelMail is a basic webmail package written in PHP4. It
includes built-in pure PHP support for the IMAP and SMTP protocols, and
all pages render in pure HTML 4.0 (with no JavaScript) for maximum
compatibility across browsers.  It has very few requirements and is very
easy to configure and install." );
	script_tag( name: "affected", value: "'squirrelmail' package(s) on Fedora 30." );
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
	if(!isnull( res = isrpmvuln( pkg: "squirrelmail", rpm: "squirrelmail~1.4.23~1.fc30.20190710", rls: "FC30" ) )){
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

