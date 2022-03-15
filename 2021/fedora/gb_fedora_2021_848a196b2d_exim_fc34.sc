if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879544" );
	script_version( "2021-08-20T09:01:03+0000" );
	script_cve_id( "CVE-2020-28007", "CVE-2020-28008", "CVE-2020-28014", "CVE-2021-27216", "CVE-2020-28011", "CVE-2020-28010", "CVE-2020-28013", "CVE-2020-28016", "CVE-2020-28015", "CVE-2020-28012", "CVE-2020-28009", "CVE-2020-28017", "CVE-2020-28020", "CVE-2020-28023", "CVE-2020-28021", "CVE-2020-28022", "CVE-2020-28026", "CVE-2020-28019", "CVE-2020-28024", "CVE-2020-28018", "CVE-2020-28025" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-20 09:01:03 +0000 (Fri, 20 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-10 16:13:00 +0000 (Mon, 10 May 2021)" );
	script_tag( name: "creation_date", value: "2021-05-07 03:16:13 +0000 (Fri, 07 May 2021)" );
	script_name( "Fedora: Security Advisory for exim (FEDORA-2021-848a196b2d)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC34" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-848a196b2d" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/FRCC2EEN34AJ2SWEZZOOWJN345XAW5VK" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'exim'
  package(s) announced via the FEDORA-2021-848a196b2d advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Exim is a message transfer agent (MTA) developed at the University of
Cambridge for use on Unix systems connected to the Internet. It is
freely available under the terms of the GNU General Public Licence. In
style it is similar to Smail 3, but its facilities are more
general. There is a great deal of flexibility in the way mail can be
routed, and there are extensive facilities for checking incoming
mail. Exim can be installed in place of sendmail, although the
configuration of exim is quite different to that of sendmail." );
	script_tag( name: "affected", value: "'exim' package(s) on Fedora 34." );
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
if(release == "FC34"){
	if(!isnull( res = isrpmvuln( pkg: "exim", rpm: "exim~4.94.2~1.fc34", rls: "FC34" ) )){
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

