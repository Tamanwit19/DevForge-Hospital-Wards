"""Local diagnostic only: repair verified checkout newline drift in a temporary truth copy.
Never used by the submission pipeline; never changes original truth or input data.
"""
import argparse, hashlib, json, pathlib, subprocess, sys, tempfile
def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--output',required=True)
    args=ap.parse_args()
    kit=pathlib.Path(__file__).resolve().parent/'Secret-Wards-ToolKit'
    original=kit/'dev'/'truth'/'truth.json'
    truth=json.loads(original.read_text(encoding='utf-8'))
    corrected=0
    for rel, record in truth['files'].items():
        data=(kit/'dev'/'input'/rel).read_bytes()
        actual=hashlib.sha256(data).hexdigest()
        if actual==record['sha256']: continue
        if hashlib.sha256(data.replace(b'\r\n',b'\n')).hexdigest()!=record['sha256']:
            sys.exit('Unverified dataset difference; diagnostic aborted')
        record['sha256']=actual
        corrected+=1
    print(f'Local diagnostic: {corrected} verified CRLF-only hash differences',flush=True)
    with tempfile.NamedTemporaryFile(mode='w',encoding='utf-8',suffix='.json',dir=original.parent,delete=False) as f:
        tmp=pathlib.Path(f.name)
        json.dump(truth,f,ensure_ascii=False)
    try:
        return subprocess.call([sys.executable,str(kit/'check_dev.py'),'--truth',str(tmp),'--output',args.output,'--show','0'])
    finally:
        tmp.unlink()
if __name__=='__main__': sys.exit(main())
