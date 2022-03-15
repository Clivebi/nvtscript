if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876278" );
	script_version( "2021-08-31T14:01:23+0000" );
	script_cve_id( "CVE-2018-1000805" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-31 14:01:23 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-15 13:28:00 +0000 (Thu, 15 Oct 2020)" );
	script_tag( name: "creation_date", value: "2019-05-07 02:42:24 +0000 (Tue, 07 May 2019)" );
	script_name( "Fedora Update for python-paramiko FEDORA-2018-ea6b328afd" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC29" );
	script_xref( name: "FEDORA", value: "2018-ea6b328afd" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/7TUDPCO5JT7VLIJ4EKN7LIOQBX6D22XC" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python-paramiko'
  package(s) announced via the FEDORA-2018-ea6b328afd advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Paramiko (a combination of the Esperanto words for 'paranoid' and
'friend') is
a module for python 2.3 or greater that implements the SSH2 protocol for secure
(encrypted and authenticated) connections to remote machines. Unlike SSL (aka
TLS), the SSH2 protocol does not require hierarchical certificates signed by a
powerful central authority. You may know SSH2 as the protocol that replaced
telnet and rsh for secure access to remote shells, but the protocol also
includes the ability to open arbitrary channels to remote services across an
encrypted tunnel (this is how sftp works, for example)." );
	script_tag( name: "affected", value: "'python-paramiko' package(s) on Fedora 29." );
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
if(release == "FC29"){
	if(!isnull( res = isrpmvuln( pkg: "python-paramiko", rpm: "python-paramiko~2.4.2~1.fc29", rls: "FC29" ) )){
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

