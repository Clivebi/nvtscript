if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876752" );
	script_version( "2021-09-02T12:01:30+0000" );
	script_cve_id( "CVE-2019-15149" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-02 12:01:30 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-30 11:38:00 +0000 (Fri, 30 Aug 2019)" );
	script_tag( name: "creation_date", value: "2019-09-05 02:26:43 +0000 (Thu, 05 Sep 2019)" );
	script_name( "Fedora Update for python-mitogen FEDORA-2019-b25dd670a4" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC30" );
	script_xref( name: "FEDORA", value: "2019-b25dd670a4" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/542TZ56SDU5EDPRPJMB6X5JFGSAHEMYK" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python-mitogen'
  package(s) announced via the FEDORA-2019-b25dd670a4 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Mitogen is a Python library for writing distributed self-replicating programs.

There is no requirement for installing packages, copying files around, writing
shell snippets, upfront configuration, or providing any secondary link to a
remote machine aside from an SSH connection. Due to its origins for use in
managing potentially damaged infrastructure, the remote machine need not even
have free disk space or a writeable filesystem.

It is not intended as a generic RPC framework, the goal is to provide a robust
and efficient low-level API on which tools like Salt, Ansible, or Fabric can be
built, and while the API is quite friendly and comparable to Fabric, ultimately
it is not intended for direct use by consumer software.

The focus is to centralize and perfect the intricate dance required to run
Python code safely and efficiently on a remote machine, while avoiding
temporary files or large chunks of error-prone shell scripts, and supporting
common privilege escalation techniques like sudo, potentially in combination
with exotic connection methods such as WMI, telnet, or console-over-IPMI." );
	script_tag( name: "affected", value: "'python-mitogen' package(s) on Fedora 30." );
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
	if(!isnull( res = isrpmvuln( pkg: "python-mitogen", rpm: "python-mitogen~0.2.8~1.fc30", rls: "FC30" ) )){
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

