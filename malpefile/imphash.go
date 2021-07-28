package malpefile

// ImpHash get impHash
func (p *PEFile) ImpHash() {
	p.Data.ImpHash, _ = p.peFile.ImpHash()
}
